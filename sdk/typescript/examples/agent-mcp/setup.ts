/**
 * Demo world for the MCP examples: one provider runtime, one agent, one grant.
 */
import {
  Agent,
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
  utcnow,
  verifyManifest,
} from "ccp-core";
import type { Grant } from "ccp-core";
import { createMcpServer } from "ccp-core/mcp";
import type { ConfirmationRequest, McpServer } from "ccp-core/mcp";

// Demo keys are deterministic so restarts keep the same grant. A real setup
// keeps the agent seed in a secret store and the provider seed on the service.
const PROVIDER_SEED = Uint8Array.from({ length: 32 }, (_, index) => index);
const AGENT_SEED = Uint8Array.from({ length: 32 }, (_, index) => index + 32);

const CATALOGUE: Record<string, { item_id: string; name: string }> = {
  "item-123": { item_id: "item-123", name: "Widget" },
};

const INTENTS = {
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
};

export interface DemoOptions {
  /** Trusted host decision. Examples supply one; the bridge never approves. */
  confirm?: (request: ConfirmationRequest) => boolean | Promise<boolean>;
}

export function createDemoAgent(options: DemoOptions = {}): {
  runtime: Runtime;
  agent: Agent;
  grant: Grant;
  bridge: McpServer;
} {
  const manifestWire = signManifest(
    {
      provider: {
        id: keyIdFromPublic(publicFromSeed(PROVIDER_SEED)),
        name: "Example Service",
      },
      version: 1,
      intents: INTENTS,
    },
    PROVIDER_SEED
  );
  const manifest = verifyManifest(manifestWire);
  const agent = new Agent(AGENT_SEED);

  const grant = createGrant({
    id: "g-agent-demo",
    requesterKey: agent.keyId,
    contactId: "c-agent-demo",
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

  const bridge = createMcpServer({
    runtime,
    agent,
    grant,
    confirm: options.confirm,
  });

  return { runtime, agent, grant, bridge };
}
