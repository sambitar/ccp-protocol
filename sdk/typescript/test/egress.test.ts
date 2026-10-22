import { describe, expect, it } from "vitest";
import { keyIdFromPublic, publicFromSeed } from "../src/crypto.js";
import { signManifest, signSignal } from "../src/requester.js";
import { verifyManifest } from "../src/consumer.js";
import { createGrant } from "../src/grants.js";
import { HostRegistry, Runtime, SchemaRegistry } from "../src/runtime.js";
import {
  MemoryAuditLog,
  MemoryGrantStore,
  MemoryManifestStore,
} from "../src/stores.js";

const NOW = "2026-10-22T12:00:30Z";
const PROVIDER_SEED = Uint8Array.from({ length: 32 }, (_, index) => index);
const REQUESTER_SEED = Uint8Array.from(
  { length: 32 },
  (_, index) => index + 32
);
const REQUESTER_PUBLIC = publicFromSeed(REQUESTER_SEED);

const PARAMS = {
  type: "object",
  properties: { q: { type: "string" } },
  required: ["q"],
  additionalProperties: false,
};
const RESULT = {
  type: "object",
  properties: { ok: { type: "boolean" } },
  required: ["ok"],
  additionalProperties: false,
};

const LOCAL_INTENT = {
  description: "Fetch something",
  params_schema: "schema:example.fetch.params.v1",
  result_schema: "schema:example.fetch.result.v1",
  required_capabilities: ["net.request"],
  placement: "local",
  data_egress: { network: false, fields: [] },
  suggested_limits: { calls_per_hour: 5 },
  confirmation: "none",
};

function world(intent: any, hostOptions: any = {}) {
  const providerId = keyIdFromPublic(publicFromSeed(PROVIDER_SEED));
  const manifest = verifyManifest(
    signManifest(
      {
        provider: { id: providerId, name: "Example Service" },
        version: 1,
        intents: { "example.fetch": intent },
      },
      PROVIDER_SEED
    )
  );
  const grant = createGrant({
    contactId: "c-1",
    requesterKey: keyIdFromPublic(publicFromSeed(REQUESTER_SEED)),
    manifest,
    intents: ["example.fetch"],
    createdAt: "2026-10-22T10:00:00Z",
    expiresAt: "2026-10-22T23:00:00Z",
  });

  const hosts = new HostRegistry();
  hosts.registerHost("net.request", () => ({ ok: true }), hostOptions);
  hosts.registerIntent("example.fetch", (params: any, access: any) =>
    access.call("net.request", params.q)
  );
  const runtime = new Runtime({
    grants: new MemoryGrantStore([grant]),
    manifests: new MemoryManifestStore([manifest]),
    schemas: new SchemaRegistry({
      "schema:example.fetch.params.v1": PARAMS,
      "schema:example.fetch.result.v1": RESULT,
    }),
    hosts,
    audit: new MemoryAuditLog(),
    clock: () => NOW,
  });
  const signal = signSignal(
    {
      requestId: "r1",
      grantDigest: manifest.digest,
      intent: "example.fetch",
      params: { q: "hello" },
      issuedAt: "2026-10-22T12:00:00Z",
      expiresAt: "2026-10-22T12:01:00Z",
    },
    REQUESTER_SEED
  );
  return { runtime, grant, signal, hosts };
}

describe("egress and placement enforcement", () => {
  it("refuses a network host under a local-only grant", async () => {
    const { runtime, signal } = world(LOCAL_INTENT, { network: true });
    const decision = await runtime.submit(signal, REQUESTER_PUBLIC);
    expect(decision.error).toBe("capability_unavailable");
    expect(decision.detail).toContain("network egress");
  });

  it("allows a network host when the manifest declares and the grant allows it", async () => {
    const intent = {
      ...LOCAL_INTENT,
      data_egress: { network: true, fields: ["q"] },
    };
    const { runtime, signal } = world(intent, {
      network: true,
      fields: ["q"],
    });
    const decision = await runtime.submit(signal, REQUESTER_PUBLIC);
    expect(decision.outcome).toBe("authorized");
    expect(decision.result).toEqual({ ok: true });
  });

  it("refuses a host that transmits an undeclared field", async () => {
    const intent = {
      ...LOCAL_INTENT,
      data_egress: { network: true, fields: ["q"] },
    };
    const { runtime, signal } = world(intent, {
      network: true,
      fields: ["q", "token"],
    });
    const decision = await runtime.submit(signal, REQUESTER_PUBLIC);
    expect(decision.error).toBe("capability_unavailable");
    expect(decision.detail).toContain("undeclared field token");
  });

  it("refuses a remote intent on a local-only host", async () => {
    const intent = {
      ...LOCAL_INTENT,
      placement: "remote",
      data_egress: { network: true, fields: ["q"] },
    };
    const { runtime, signal } = world(intent, { network: true });
    const decision = await runtime.submit(signal, REQUESTER_PUBLIC);
    expect(decision.error).toBe("capability_unavailable");
    expect(decision.detail).toContain("placement");
  });

  it("allows a remote intent on a host that declares the placement", async () => {
    const intent = {
      ...LOCAL_INTENT,
      placement: "remote",
      data_egress: { network: true, fields: ["q"] },
    };
    const { runtime, signal } = world(intent, {
      network: true,
      placement: ["remote"],
      fields: ["q"],
    });
    const decision = await runtime.submit(signal, REQUESTER_PUBLIC);
    expect(decision.outcome).toBe("authorized");
  });

  it("enforces the ceiling again on a direct host call", () => {
    const hosts = new HostRegistry();
    hosts.registerHost("net.request", () => "ok", { network: true });
    const access = hosts.access(["net.request"], {
      network: false,
      fields: new Set(),
    });
    expect(() => access.call("net.request")).toThrow(/network egress/);
  });

  it("defaults an unannotated host to local and no egress", () => {
    const hosts = new HostRegistry();
    hosts.registerHost("store.read", () => "ok");
    expect(hosts.hostMeta("store.read")).toMatchObject({
      network: false,
      placement: ["local"],
      fields: [],
    });
    const access = hosts.access(["store.read"], {
      network: false,
      fields: new Set(),
    });
    expect(access.call("store.read")).toBe("ok");
  });
});
