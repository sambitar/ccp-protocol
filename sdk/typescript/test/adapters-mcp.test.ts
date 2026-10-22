import { describe, expect, it } from "vitest";

import { createMcpServer } from "../src/adapters/mcp.js";
import type { ConfirmationRequest } from "../src/adapters/mcp.js";
import { Agent } from "../src/agent.js";
import {
  PARAMS_SCHEMA,
  RESULT_SCHEMA,
  REQUESTER_SEED,
  STRANGER_SEED,
  buildWorld,
} from "./world.js";
import type { WorldOptions } from "./world.js";

type Confirm = (request: ConfirmationRequest) => boolean | Promise<boolean>;

function build(options: WorldOptions = {}, confirm?: Confirm) {
  const world = buildWorld(options);
  const agent = new Agent(REQUESTER_SEED);
  const server = createMcpServer({
    runtime: world.runtime,
    agent,
    grant: world.grant,
    confirm,
  });
  return { world, agent, server };
}

function body(result: { content: { type: "text"; text: string }[] }) {
  return JSON.parse(result.content[0].text);
}

const CALL = { item_id: "item-123" };

describe("createMcpServer", () => {
  it("lists the granted intent as a tool with its registered schemas", () => {
    const { server } = build();

    expect(server.tools.map((tool) => tool.name)).toEqual(["example.lookup"]);
    const tool = server.tools[0];
    expect(tool.inputSchema).toEqual(PARAMS_SCHEMA);
    expect(tool.outputSchema).toEqual(RESULT_SCHEMA);
    expect(tool.description).toContain('"example.lookup"');
    expect(tool.description).toContain("untrusted");
  });

  it("runs an authorized tool call and returns the result as data", async () => {
    const { server } = build();

    const result = await server.callTool("example.lookup", CALL);

    expect(result.isError).toBeUndefined();
    expect(body(result)).toEqual({ item_id: "item-123", name: "Widget" });
    expect(result.structuredContent).toEqual({
      item_id: "item-123",
      name: "Widget",
    });
  });

  it("refuses an ungranted tool", async () => {
    const { server } = build();

    const result = await server.callTool("files.search", {});

    expect(result.isError).toBe(true);
    expect(body(result).outcome).toBe("intent_not_allowed");
  });

  it("refuses non-object arguments", async () => {
    const { server } = build();

    const result = await server.callTool("example.lookup", "item-123");

    expect(result.isError).toBe(true);
    expect(body(result).outcome).toBe("invalid_request");
  });

  it("surfaces confirmation_required when the host offers no decision", async () => {
    const { server } = build({ confirmation: "per_action" });

    const result = await server.callTool("example.lookup", CALL);
    const data = body(result);

    expect(result.isError).toBe(true);
    expect(data.outcome).toBe("confirmation_required");
    expect(typeof data.pending_id).toBe("string");
    expect(typeof data.request_id).toBe("string");
    expect(data.error).toBeUndefined();
  });

  it("executes after the host approves, with the exact action in the card", async () => {
    const seen: ConfirmationRequest[] = [];
    const { server } = build({ confirmation: "per_action" }, async (request) => {
      seen.push(request);
      return true;
    });

    const result = await server.callTool("example.lookup", CALL);

    expect(result.isError).toBeUndefined();
    expect(body(result)).toEqual({ item_id: "item-123", name: "Widget" });
    expect(seen).toHaveLength(1);
    expect(seen[0].intent).toBe("example.lookup");
    expect(seen[0].params).toEqual(CALL);
    expect(seen[0].card.who).toBe("Example Service");
    expect(seen[0].card.what).toBe(
      "Look up one item requested by the consumer"
    );
  });

  it("does not execute when the host denies", async () => {
    const { server } = build({ confirmation: "per_action" }, () => false);

    const result = await server.callTool("example.lookup", CALL);

    expect(result.isError).toBe(true);
    expect(body(result).outcome).toBe("cancelled");
    expect(body(result).error).toBeUndefined();
  });

  it("treats a thrown host decision as denial", async () => {
    const { server } = build({ confirmation: "per_action" }, () => {
      throw new Error("no trusted ui available");
    });

    const result = await server.callTool("example.lookup", CALL);

    expect(body(result).outcome).toBe("cancelled");
  });

  it("reports limit_exceeded on the call after the limit", async () => {
    const { server } = build({ limits: { calls_per_hour: 1 } });

    const first = await server.callTool("example.lookup", CALL);
    const second = await server.callTool("example.lookup", CALL);

    expect(first.isError).toBeUndefined();
    expect(body(second).outcome).toBe("limit_exceeded");
    expect(body(second).error).toBe("limit_exceeded");
  });

  it("refuses to build for a grant bound to another key", () => {
    const world = buildWorld();

    expect(() =>
      createMcpServer({
        runtime: world.runtime,
        agent: new Agent(STRANGER_SEED),
        grant: world.grant,
      })
    ).toThrow(/not bound/);
  });

  it("reports a revoked grant", async () => {
    const { server } = build({ state: "revoked" });

    const result = await server.callTool("example.lookup", CALL);

    expect(body(result).outcome).toBe("grant_revoked");
  });
});
