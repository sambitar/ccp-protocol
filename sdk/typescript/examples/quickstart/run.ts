/**
 * The end-to-end CCP loop, runnable.
 *
 * Run with `npm run quickstart`. It signs a manifest, approves one intent,
 * submits a signed signal, then revokes the grant and shows the next request
 * being refused.
 */
import {
  HostRegistry,
  MemoryAuditLog,
  MemoryGrantStore,
  MemoryManifestStore,
  Runtime,
  SchemaRegistry,
  createGrant,
  keyIdFromPublic,
  publicFromSeed,
  signManifest,
  signSignal,
  verifyManifest,
} from "ccp-core";

const PROVIDER_SEED = Uint8Array.from({ length: 32 }, (_, index) => index);
const REQUESTER_SEED = Uint8Array.from(
  { length: 32 },
  (_, index) => index + 32
);
const REQUESTER_PUBLIC = publicFromSeed(REQUESTER_SEED);

const NOW = "2026-10-22T12:00:00Z";
const UNTIL = "2030-01-01T00:00:00Z";

const PARAMS_SCHEMA = {
  type: "object",
  properties: { item_id: { type: "string" } },
  required: ["item_id"],
  additionalProperties: false,
};
const RESULT_SCHEMA = {
  type: "object",
  properties: {
    item_id: { type: "string" },
    name: { type: "string" },
  },
  required: ["item_id", "name"],
  additionalProperties: false,
};

// 1. The provider publishes a signed manifest. Publishing grants nothing.
const manifestWire = signManifest(
  {
    provider: {
      id: keyIdFromPublic(publicFromSeed(PROVIDER_SEED)),
      name: "Example Service",
    },
    version: 1,
    intents: {
      "example.lookup": {
        description: "Look up one item the consumer asked for",
        params_schema: "schema:example.lookup.params.v1",
        result_schema: "schema:example.lookup.result.v1",
        required_capabilities: ["store.read"],
        placement: "local",
        data_egress: { network: false, fields: [] },
        suggested_limits: { calls_per_hour: 5 },
        confirmation: "none",
      },
    },
  },
  PROVIDER_SEED
);
const manifest = verifyManifest(manifestWire);

// 2. The consumer approves one intent. This is the only source of authority.
const grant = createGrant({
  contactId: "c-1",
  requesterKey: keyIdFromPublic(publicFromSeed(REQUESTER_SEED)),
  manifest,
  intents: ["example.lookup"],
  createdAt: "2026-10-22T10:00:00Z",
  expiresAt: UNTIL,
});

// 3. The runtime owns execution. The host is local and offline.
const hosts = new HostRegistry();
hosts.registerHost("store.read", (itemId: string) => ({
  item_id: itemId,
  name: "Widget",
}));
hosts.registerIntent("example.lookup", (params: any, access: any) =>
  access.call("store.read", params.item_id)
);

const runtime = new Runtime({
  grants: new MemoryGrantStore([grant]),
  manifests: new MemoryManifestStore([manifest]),
  schemas: new SchemaRegistry({
    "schema:example.lookup.params.v1": PARAMS_SCHEMA,
    "schema:example.lookup.result.v1": RESULT_SCHEMA,
  }),
  hosts,
  audit: new MemoryAuditLog(),
  clock: () => NOW,
});

// 4. The requester signs a signal bound to the manifest digest.
const signal = signSignal(
  {
    requestId: "req-1",
    grantDigest: manifest.digest,
    intent: "example.lookup",
    params: { item_id: "item-123" },
    issuedAt: "2026-10-22T11:59:00Z",
    expiresAt: "2026-10-22T12:01:00Z",
  },
  REQUESTER_SEED
);

const decision = await runtime.submit(signal, REQUESTER_PUBLIC);
console.log("decision:", decision.outcome, JSON.stringify(decision.result));

// 5. Revocation is local and permanent.
await runtime.revokeGrant(grant.id, "demo revoke");

const afterRevoke = await runtime.submit(
  signSignal(
    {
      requestId: "req-2",
      grantDigest: manifest.digest,
      intent: "example.lookup",
      params: { item_id: "item-123" },
      issuedAt: "2026-10-22T11:59:00Z",
      expiresAt: "2026-10-22T12:01:00Z",
    },
    REQUESTER_SEED
  ),
  REQUESTER_PUBLIC
);
console.log("after revoke:", afterRevoke.error);
