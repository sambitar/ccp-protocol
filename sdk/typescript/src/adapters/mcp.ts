import type { Agent } from "../agent.js";
import type { PermissionCard, VerifiedManifest } from "../consumer.js";
import type { JsonValue } from "../json.js";
import type { Decision, Runtime } from "../runtime.js";
import type { Grant } from "../stores.js";
import { permissionCard } from "../consumer.js";
import { confirmationPolicy } from "../decision.js";
import { AUTHORIZED, CONFIRMATION_REQUIRED, ERROR_CODES } from "../errors.js";
import { randomId } from "../ids.js";

export interface McpTool {
  /** Intent name, used verbatim as the MCP tool name. */
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
}

export interface McpTextContent {
  type: "text";
  text: string;
}

export interface McpToolResult {
  content: McpTextContent[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

/** The exact action a trusted host is asked to approve (§11.4). */
export interface ConfirmationRequest {
  pendingId: string;
  requestId: string;
  intent: string;
  params: Record<string, JsonValue>;
  card: PermissionCard;
}

export interface McpServerOptions {
  /** Runtime that owns grants, limits, replay protection, and executors. */
  runtime: Runtime;
  /** Agent key that signs each tool call and that the grant is bound to. */
  agent: Agent;
  /** The agent's whole authority. Create one bridge per grant. */
  grant: Grant;
  /** Defaults to the runtime's verified manifest for this grant. */
  manifest?: VerifiedManifest;
  /**
   * Trusted host decision. Omit to surface `confirmation_required` to the
   * caller instead. The adapter never approves on its own.
   */
  confirm?: (request: ConfirmationRequest) => boolean | Promise<boolean>;
  /** Lifetime of each signed signal, in seconds. Default 60. */
  requestTtlSeconds?: number;
  /** Defaults to `runtime.clock`. */
  now?: () => string;
}

export interface McpServer {
  readonly tools: readonly McpTool[];
  callTool(name: string, args: unknown): Promise<McpToolResult>;
}

/**
 * Transport-neutral MCP bridge. Expose `tools` through an MCP host and route
 * `tools/call` to `callTool`; the runtime makes every authorization decision.
 */
export function createMcpServer(options: McpServerOptions): McpServer {
  const { runtime, agent, grant } = options;
  const manifest =
    options.manifest ?? runtime.manifests.get(grant.manifest_digest);
  if (manifest === undefined) {
    throw new Error(`manifest not found for grant ${grant.id}`);
  }
  const verified = manifest;
  if (grant.requester_key !== agent.keyId) {
    throw new Error(`grant ${grant.id} is not bound to this agent key`);
  }

  const now = options.now ?? runtime.clock;
  const ttl = options.requestTtlSeconds ?? 60;
  const tools: McpTool[] = [];

  for (const intent of grant.intents) {
    const definition = verified.manifest.intents?.[intent];
    if (definition === undefined) {
      throw new Error(`intent ${intent} is not declared in the manifest`);
    }
    const inputSchema = runtime.schemas.get(definition.params_schema);
    if (inputSchema === undefined) {
      throw new Error(
        `params schema not registered: ${definition.params_schema}`
      );
    }
    const outputSchema = runtime.schemas.get(definition.result_schema);
    tools.push({
      name: intent,
      description: describe(intent, definition, grant),
      inputSchema,
      ...(outputSchema === undefined ? {} : { outputSchema }),
    });
  }

  const byName = new Map(tools.map((tool) => [tool.name, tool]));

  async function settle(
    decision: Decision,
    tool: McpTool,
    intent: string,
    params: Record<string, JsonValue>
  ): Promise<McpToolResult> {
    if (decision.outcome === AUTHORIZED) return success(tool, decision.result);
    if (decision.outcome !== CONFIRMATION_REQUIRED) {
      return failure(decision.outcome, {
        request_id: decision.request_id,
        detail: decision.detail,
      });
    }

    const pendingId = decision.pending_id;
    if (pendingId === undefined) return failure("invalid_request");

    if (options.confirm === undefined) {
      return failure(CONFIRMATION_REQUIRED, {
        request_id: decision.request_id,
        pending_id: pendingId,
      });
    }

    let approved = false;
    try {
      approved = await options.confirm({
        pendingId,
        requestId: decision.request_id ?? "",
        intent,
        params,
        card: permissionCard(verified.manifest, intent),
      });
    } catch {
      approved = false;
    }

    const resolved = await runtime.confirm(pendingId, approved);
    if (resolved.outcome === AUTHORIZED) return success(tool, resolved.result);
    if (resolved.outcome === "cancelled") {
      return failure("cancelled", { request_id: resolved.request_id });
    }
    return failure(resolved.outcome, {
      request_id: resolved.request_id,
      detail: resolved.detail,
    });
  }

  return {
    tools,
    async callTool(name, args) {
      try {
        const tool = byName.get(name);
        if (tool === undefined) return failure("intent_not_allowed");
        if (args === null || typeof args !== "object" || Array.isArray(args)) {
          return failure("invalid_request");
        }

        const params = args as Record<string, JsonValue>;
        const issuedAt = now();
        const expiresAt = shiftSeconds(issuedAt, ttl);
        const signal = agent.signalFor({ intent: name, params }, grant, {
          requestId: randomId(),
          issuedAt,
          expiresAt,
        });
        const decision = await runtime.submit(signal, agent.publicKey);
        return await settle(decision, tool, name, params);
      } catch {
        return failure("outcome_unknown");
      }
    },
  };
}

function describe(intent: string, definition: any, grant: Grant): string {
  const providerText =
    typeof definition.description === "string" ? definition.description : "";
  const policy = confirmationPolicy(grant, definition, intent);
  return (
    `User-granted CCP capability "${intent}". ` +
    `Provider description (untrusted data): ${JSON.stringify(providerText)}. ` +
    (policy === "per_action"
      ? "Each call may require explicit user confirmation. "
      : "No per-call confirmation is required. ") +
    "The user's runtime enforces this capability."
  );
}

function success(tool: McpTool, result: unknown): McpToolResult {
  const content: McpTextContent[] = [
    { type: "text", text: JSON.stringify(result) ?? "null" },
  ];
  const isObject =
    result !== null && typeof result === "object" && !Array.isArray(result);
  return tool.outputSchema !== undefined && isObject
    ? { content, structuredContent: result as Record<string, unknown> }
    : { content };
}

function failure(
  outcome: string,
  extra: Record<string, unknown> = {}
): McpToolResult {
  const body: Record<string, unknown> = { outcome };
  if (ERROR_CODES.has(outcome)) body.error = outcome;
  for (const [key, value] of Object.entries(extra)) {
    if (value !== undefined) body[key] = value;
  }
  return {
    content: [{ type: "text", text: JSON.stringify(body) }],
    isError: true,
  };
}

function shiftSeconds(timestamp: string, seconds: number): string {
  return new Date(Date.parse(timestamp) + seconds * 1000)
    .toISOString()
    .replace(/\.\d+Z$/, "Z");
}
