/**
 * Runnable CCP provider.
 *
 * Serves one signed manifest, provisions one demo grant, and accepts signed
 * signals through the Express adapter. Run with `npm run provider`.
 */
import express from "express";

import {
  MemoryAuditLog,
  MemoryGrantStore,
  MemoryManifestStore,
  HostRegistry,
  Runtime,
  SchemaRegistry,
  createGrant,
  keyIdFromPublic,
  publicFromSeed,
  signManifest,
  signSignal,
  utcnow,
  verifyManifest,
} from "ccp-core";
import { providerMiddleware } from "ccp-core/express";

const PORT = Number(process.env.PORT ?? 8787);

// Demo keys are deterministic so restarts produce the same grant. A real
// provider keeps its seed in a secret store and never prints it.
const PROVIDER_SEED = Uint8Array.from({ length: 32 }, (_, index) => index);
const DEMO_REQUESTER_SEED = Uint8Array.from(
  { length: 32 },
  (_, index) => index + 32
);
const DEMO_REQUESTER_KEY = publicFromSeed(DEMO_REQUESTER_SEED);

const CATALOGUE: Record<string, { item_id: string; name: string }> = {
  "item-123": { item_id: "item-123", name: "Widget" },
};

const manifestWire = signManifest(
  {
    provider: {
      id: keyIdFromPublic(publicFromSeed(PROVIDER_SEED)),
      name: "Example Service",
    },
    version: 1,
    intents: {
      "example.lookup": {
        description: "Look up one item from the provider's catalogue",
        params_schema: "schema:example.lookup.params.v1",
        result_schema: "schema:example.lookup.result.v1",
        required_capabilities: ["store.read"],
        placement: "local",
        data_egress: { network: false, fields: [] },
        suggested_limits: { calls_per_hour: 10 },
        confirmation: "per_action",
      },
    },
  },
  PROVIDER_SEED
);
const manifest = verifyManifest(manifestWire);

const grant = createGrant({
  id: "g-demo",
  requesterKey: keyIdFromPublic(DEMO_REQUESTER_KEY),
  contactId: "c-demo",
  manifest,
  intents: ["example.lookup"],
  createdAt: utcnow(),
  expiresAt: "2030-01-01T00:00:00Z",
});

const hosts = new HostRegistry();
hosts.registerHost("store.read", (itemId: string) => CATALOGUE[itemId]);
hosts.registerIntent("example.lookup", (params: any, access: any) =>
  access.call("store.read", params.item_id)
);

const runtime = new Runtime({
  grants: new MemoryGrantStore([grant]),
  manifests: new MemoryManifestStore([manifest]),
  schemas: new SchemaRegistry({
    "schema:example.lookup.params.v1": {
      type: "object",
      properties: { item_id: { type: "string" } },
      required: ["item_id"],
      additionalProperties: false,
    },
    "schema:example.lookup.result.v1": {
      type: "object",
      properties: { item_id: { type: "string" }, name: { type: "string" } },
      required: ["item_id", "name"],
      additionalProperties: false,
    },
  }),
  hosts,
  audit: new MemoryAuditLog(),
});

const app = express();
app.use(express.json({ limit: "64kb" }));

// The signed manifest is served verbatim so consumers can verify it.
app.get("/manifest", (_request, response) => {
  response.type("application/json").send(manifestWire);
});

/**
 * Production providers resolve the key from the authenticated channel (an
 * API token bound to a stored contact), not from the signal itself. The
 * demo knows a single requester.
 */
app.post(
  "/ccp",
  providerMiddleware({
    runtime,
    keyResolver: () => DEMO_REQUESTER_KEY,
  })
);

// A real confirmation comes from the provider's own trusted UI or device.
app.post("/ccp/confirm", async (request, response) => {
  const body = request.body as Record<string, unknown> | undefined;
  const pendingId = body?.pending_id;
  const approved = body?.approved;
  if (typeof pendingId !== "string" || typeof approved !== "boolean") {
    response
      .status(400)
      .json({ outcome: "invalid_request", error: "invalid_request" });
    return;
  }

  const decision = await runtime.confirm(pendingId, approved);
  const status =
    decision.outcome === "authorized" || decision.outcome === "cancelled"
      ? 200
      : decision.outcome === "invalid_request"
        ? 400
        : 409;
  response.status(status).json(decision);
});

app.listen(PORT, () => {
  const issuedAt = utcnow();
  const expiresAt = new Date(Date.parse(issuedAt) + 5 * 60_000)
    .toISOString()
    .replace(/\.\d+Z$/, "Z");
  const signal = signSignal(
    {
      requestId: `demo-${Date.now().toString(36)}`,
      grantDigest: manifest.digest,
      intent: "example.lookup",
      params: { item_id: "item-123" },
      issuedAt,
      expiresAt,
    },
    DEMO_REQUESTER_SEED
  );

  console.log(`CCP provider listening on http://127.0.0.1:${PORT}`);
  console.log(`manifest digest: ${manifest.digest}`);
  console.log("\n1. Submit this single-use signal:");
  console.log(
    `curl -s http://127.0.0.1:${PORT}/ccp -H 'content-type: application/json' -d '${JSON.stringify(
      { signal }
    )}'`
  );
  console.log("\n2. Approve the returned pending_id:");
  console.log(
    `curl -s http://127.0.0.1:${PORT}/ccp/confirm -H 'content-type: application/json' -d '{"pending_id":"<pending_id>","approved":true}'`
  );
  console.log("\nRestart the server for a fresh demo signal.");
});
