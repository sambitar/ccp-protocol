import { signManifest, signSignal } from "../src/requester.js";
import { verifyManifest } from "../src/consumer.js";
import { keyIdFromPublic, publicFromSeed } from "../src/crypto.js";
import {
  HostRegistry,
  Runtime,
  SchemaRegistry,
} from "../src/runtime.js";
import {
  Grant,
  MemoryAuditLog,
  MemoryGrantStore,
  MemoryManifestStore,
} from "../src/stores.js";

export const NOW = "2026-10-22T12:00:30Z";
export const PROVIDER_SEED = Uint8Array.from({ length: 32 }, (_, i) => i);
export const REQUESTER_SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 32);
export const STRANGER_SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 64);
export const REQUESTER_PUBLIC = publicFromSeed(REQUESTER_SEED);

export const STORE: Record<string, any> = {
  "item-123": { item_id: "item-123", name: "Widget" },
};

export const PARAMS_SCHEMA = {
  type: "object",
  properties: { item_id: { type: "string" } },
  required: ["item_id"],
  additionalProperties: false,
};
export const RESULT_SCHEMA = {
  type: "object",
  properties: { item_id: { type: "string" }, name: { type: "string" } },
  required: ["item_id", "name"],
  additionalProperties: false,
};
export const INTENTS = {
  "example.lookup": {
    description: "Look up one item requested by the consumer",
    params_schema: "schema:example.lookup.params.v1",
    result_schema: "schema:example.lookup.result.v1",
    required_capabilities: ["store.read"],
    placement: "local",
    data_egress: { network: false, fields: [] },
    suggested_limits: { calls_per_hour: 10 },
    confirmation: "grant-policy",
  },
};

export interface WorldOptions {
  confirmation?: string;
  limits?: Record<string, number>;
  capabilities?: string[];
  expiresAt?: string;
  state?: string;
  now?: string;
}

export function buildWorld(options: WorldOptions = {}) {
  const providerId = keyIdFromPublic(publicFromSeed(PROVIDER_SEED));
  const requesterId = keyIdFromPublic(publicFromSeed(REQUESTER_SEED));
  const manifestWire = signManifest(
    {
      provider: { id: providerId, name: "Example Service" },
      version: 1,
      intents: INTENTS,
    },
    PROVIDER_SEED
  );
  const manifest = verifyManifest(manifestWire);
  const grant: Grant = {
    id: "g-1",
    requester_key: requesterId,
    contact_id: "c-1",
    manifest_digest: manifest.digest,
    manifest_version: 1,
    intents: ["example.lookup"],
    limits: options.limits ?? { calls_per_hour: 10 },
    created_at: "2026-10-22T10:00:00Z",
    expires_at: options.expiresAt ?? "2026-10-22T23:00:00Z",
    confirmation: { "example.lookup": options.confirmation ?? "none" },
    capabilities: options.capabilities ?? ["store.read"],
    placement: ["local"],
    egress: { network: false },
    state: options.state ?? "active",
    state_reason: null,
  };
  const schemas = new SchemaRegistry({
    "schema:example.lookup.params.v1": PARAMS_SCHEMA,
    "schema:example.lookup.result.v1": RESULT_SCHEMA,
  });
  const hosts = new HostRegistry();
  hosts.registerHost("store.read", (id: string) => STORE[id]);
  hosts.registerIntent("example.lookup", (params: any, access: any) =>
    access.call("store.read", params.item_id)
  );
  const runtime = new Runtime({
    grants: new MemoryGrantStore([grant]),
    manifests: new MemoryManifestStore([manifest]),
    schemas,
    hosts,
    audit: new MemoryAuditLog(),
    clock: () => options.now ?? NOW,
  });
  return { runtime, grant, manifest, manifestWire, requesterId };
}

export function signalFor(
  world: ReturnType<typeof buildWorld>,
  options: any = {}
): string {
  return signSignal(
    {
      requestId: options.requestId ?? "req-1",
      grantDigest: options.grantDigest ?? world.manifest.digest,
      intent: options.intent ?? "example.lookup",
      params: options.params ?? { item_id: "item-123" },
      issuedAt: "2026-10-22T12:00:00Z",
      expiresAt: options.expiresAt ?? "2026-10-22T12:01:00Z",
      ccp: options.ccp ?? "0.5-draft",
    },
    options.signer ?? REQUESTER_SEED
  );
}
