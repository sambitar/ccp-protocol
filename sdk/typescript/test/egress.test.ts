import { describe, expect, it } from "vitest";
import { keyIdFromPublic, publicFromSeed } from "../src/crypto.js";
import { signManifest, signSignal } from "../src/requester.js";
import { verifyManifest } from "../src/consumer.js";
import { createGrant } from "../src/grants.js";
import {
  buildAdmissionPolicy,
  verifyAdmissionPolicy,
} from "../src/identity.js";
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
  return { runtime, grant, signal, hosts, manifest };
}

describe("egress and placement enforcement", () => {
  it("refuses a network host under a local-only grant", async () => {
    const { runtime, signal } = world(LOCAL_INTENT, {
      class: "disclose",
      network: true,
      fields: ["q"],
    });
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
      class: "disclose",
      network: true,
      fields: ["q"],
    });
    const first = await runtime.submit(signal, REQUESTER_PUBLIC);
    expect(first.outcome).toBe("confirmation_required");
    const done = await runtime.confirm(first.pending_id!, true);
    expect(done.outcome).toBe("authorized");
    expect(done.result).toEqual({ ok: true });
  });

  it("refuses a host that transmits an undeclared field", async () => {
    const intent = {
      ...LOCAL_INTENT,
      data_egress: { network: true, fields: ["q"] },
    };
    const { runtime, signal } = world(intent, {
      class: "disclose",
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
    const { runtime, signal } = world(intent, {
      class: "disclose",
      network: true,
      fields: ["q"],
    });
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
      class: "disclose",
      network: true,
      placement: ["local", "remote"],
      fields: ["q"],
    });
    const first = await runtime.submit(signal, REQUESTER_PUBLIC);
    expect(first.outcome).toBe("confirmation_required");
    const done = await runtime.confirm(first.pending_id!, true);
    expect(done.outcome).toBe("authorized");
  });

  it("enforces the ceiling again on a direct host call", () => {
    const hosts = new HostRegistry();
    hosts.registerHost("net.request", () => "ok", {
      class: "disclose",
      network: true,
      fields: ["q"],
    });
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
      profile: {
        network: false,
        placement: ["local"],
        fields: [],
        class: "read",
        risk: "read",
        minConfirmation: "none",
      },
    });
    const access = hosts.access(["store.read"], {
      network: false,
      fields: new Set(),
    });
    expect(access.call("store.read")).toBe("ok");
  });

  it("never lets a policy admit an intent whose host needs a human", async () => {
    const intent = {
      ...LOCAL_INTENT,
      data_egress: { network: true, fields: ["q"] },
    };
    const { runtime, grant, manifest } = world(intent, {
      class: "disclose",
      network: true,
      fields: ["q"],
    });
    const policy = verifyAdmissionPolicy(
      buildAdmissionPolicy(
        {
          version: 1,
          default: "confirm",
          rules: [
            {
              id: "r-fetch",
              contacts: ["c-1"],
              intents: ["example.fetch"],
              risk: "read",
              limits: { calls_per_hour: 5 },
              confirmation: "none",
              expires_at: "2027-01-01T00:00:00Z",
            },
          ],
          issuedAt: "2026-10-22T00:00:00Z",
          expiresAt: "2027-01-01T00:00:00Z",
        },
        Uint8Array.from({ length: 32 }, (_, index) => index + 96)
      ),
      { now: NOW }
    );

    const outcome = await runtime.admitRequest({
      policy,
      manifest,
      request: {
        requesterKey: grant.requester_key,
        contactId: "c-1",
        intent: "example.fetch",
        risk: "read",
        now: NOW,
      },
    });
    expect(outcome.result.decision).toBe("deny");
    expect(outcome.result.reason).toBe("risk_not_admittable");
    expect(outcome.grant).toBeUndefined();
  });
});
