import type { Runtime } from "../runtime.js";
import { httpStatusFor } from "./status.js";

/** Resolve the requester's Ed25519 public key, or `undefined` if unknown. */
export type WebKeyResolver = (
  request: Request
) => Uint8Array | undefined | Promise<Uint8Array | undefined>;

export interface SignalHandlerOptions {
  /** Runtime that owns grants, replay protection, limits, and executors. */
  runtime: Runtime;
  /** Key for the sender of this request; `undefined` rejects with 401. */
  keyResolver: WebKeyResolver;
}

/**
 * Framework-neutral Web handler: POST the canonical signal JSON as the body.
 * Suitable for a Next.js route handler (`export const POST = ...`) or any
 * runtime that speaks standard `Request`/`Response`.
 */
export function createSignalHandler(
  options: SignalHandlerOptions
): (request: Request) => Promise<Response> {
  const { runtime, keyResolver } = options;

  return async (request) => {
    if (request.method !== "POST") {
      return json(405, { outcome: "invalid_request", error: "invalid_request" });
    }

    let document: string;
    try {
      document = await request.text();
    } catch {
      return json(400, {
        outcome: "invalid_request",
        error: "invalid_request",
      });
    }
    if (document.trim() === "") {
      return json(400, { outcome: "invalid_request", error: "invalid_request" });
    }

    let publicKey: Uint8Array | undefined;
    try {
      publicKey = await keyResolver(request);
    } catch {
      publicKey = undefined;
    }
    if (publicKey === undefined) {
      return json(401, { outcome: "unauthenticated", error: "unauthenticated" });
    }

    try {
      const decision = await runtime.submit(document, publicKey);
      return json(httpStatusFor(decision), decision);
    } catch {
      return json(500, { outcome: "outcome_unknown", error: "outcome_unknown" });
    }
  };
}

export interface ManifestHandlerOptions {
  /** Signed manifest wire, exactly as produced by `signManifest`. */
  manifest: string;
}

/**
 * Serve the signed manifest verbatim. Consumers verify it themselves; the
 * adapter does not re-serialize it.
 */
export function createManifestHandler(
  options: ManifestHandlerOptions
): (request: Request) => Promise<Response> {
  return async (request) => {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return json(405, { outcome: "invalid_request", error: "invalid_request" });
    }
    return new Response(request.method === "HEAD" ? null : options.manifest, {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
