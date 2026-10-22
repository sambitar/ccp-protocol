import { describe, expect, it } from "vitest";
import {
  createManifestHandler,
  createSignalHandler,
} from "../src/adapters/next.js";
import { verifyManifest } from "../src/consumer.js";
import { REQUESTER_PUBLIC, buildWorld, signalFor } from "./world.js";

const URL = "http://localhost/api/ccp";

function handlerFor(
  world: ReturnType<typeof buildWorld>,
  key: Uint8Array | null = REQUESTER_PUBLIC
) {
  return createSignalHandler({
    runtime: world.runtime,
    keyResolver: () => key ?? undefined,
  });
}

async function post(
  handler: ReturnType<typeof handlerFor>,
  body: string
): Promise<{ status: number; json: any }> {
  const response = await handler(
    new Request(URL, { method: "POST", body })
  );
  return { status: response.status, json: await response.json() };
}

describe("Next signal handler", () => {
  it("authorizes a signed signal", async () => {
    const world = buildWorld();
    const result = await post(handlerFor(world), signalFor(world));
    expect(result.status).toBe(200);
    expect(result.json.outcome).toBe("authorized");
  });

  it("rejects a tampered signal with 403", async () => {
    const world = buildWorld();
    const tampered = signalFor(world).replace('"item-123"', '"item-999"');
    const result = await post(handlerFor(world), tampered);
    expect(result.status).toBe(403);
    expect(result.json.error).toBe("unauthenticated");
  });

  it("rejects malformed JSON with 400", async () => {
    const world = buildWorld();
    const result = await post(handlerFor(world), "{ not json");
    expect(result.status).toBe(400);
    expect(result.json.error).toBe("invalid_request");
  });

  it("rejects an unknown sender with 401", async () => {
    const world = buildWorld();
    const result = await post(handlerFor(world, null), signalFor(world));
    expect(result.status).toBe(401);
    expect(result.json.error).toBe("unauthenticated");
  });

  it("rejects a non-POST request with 405", async () => {
    const world = buildWorld();
    const response = await handlerFor(world)(new Request(URL));
    expect(response.status).toBe(405);
  });
});

describe("Next manifest handler", () => {
  it("serves the signed manifest verbatim", async () => {
    const world = buildWorld();
    const handler = createManifestHandler({ manifest: world.manifestWire });
    const response = await handler(new Request(URL));

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(verifyManifest(await response.text()).digest).toBe(
      world.manifest.digest
    );
  });

  it("rejects a write with 405", async () => {
    const world = buildWorld();
    const handler = createManifestHandler({ manifest: world.manifestWire });
    const response = await handler(new Request(URL, { method: "POST" }));
    expect(response.status).toBe(405);
  });
});
