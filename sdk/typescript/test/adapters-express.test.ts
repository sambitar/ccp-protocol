import express from "express";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { providerMiddleware } from "../src/adapters/express.js";
import { REQUESTER_PUBLIC, buildWorld, signalFor } from "./world.js";

function appFor(
  world: ReturnType<typeof buildWorld>,
  key: Uint8Array | null = REQUESTER_PUBLIC
) {
  const app = express();
  app.use(express.json());
  app.post(
    "/ccp",
    providerMiddleware({
      runtime: world.runtime,
      keyResolver: () => key ?? undefined,
    })
  );
  return app;
}

async function post(
  app: express.Express,
  body: unknown
): Promise<{ status: number; json: any }> {
  const server = app.listen(0);
  const { port } = server.address() as AddressInfo;
  try {
    const response = await fetch(`http://127.0.0.1:${port}/ccp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: response.status, json: await response.json() };
  } finally {
    server.close();
  }
}

describe("Express provider middleware", () => {
  it("authorizes a signed signal", async () => {
    const world = buildWorld();
    const result = await post(appFor(world), { signal: signalFor(world) });
    expect(result.status).toBe(200);
    expect(result.json.outcome).toBe("authorized");
  });

  it("rejects a tampered signal with 403", async () => {
    const world = buildWorld();
    const tampered = signalFor(world).replace('"item-123"', '"item-999"');
    const result = await post(appFor(world), { signal: tampered });
    expect(result.status).toBe(403);
    expect(result.json.error).toBe("unauthenticated");
  });

  it("rejects a missing body with 400", async () => {
    const world = buildWorld();
    const result = await post(appFor(world), {});
    expect(result.status).toBe(400);
    expect(result.json.error).toBe("invalid_request");
  });

  it("rejects an unknown sender with 401", async () => {
    const world = buildWorld();
    const result = await post(appFor(world, null), {
      signal: signalFor(world),
    });
    expect(result.status).toBe(401);
    expect(result.json.error).toBe("unauthenticated");
  });
});
