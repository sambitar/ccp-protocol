import type { Request, RequestHandler } from "express";

import type { Runtime } from "../runtime.js";
import { httpStatusFor } from "./status.js";

/** Resolve the requester's Ed25519 public key, or `undefined` if unknown. */
export type ExpressKeyResolver = (
  request: Request
) => Uint8Array | undefined | Promise<Uint8Array | undefined>;

export interface ProviderMiddlewareOptions {
  /** Runtime that owns grants, replay protection, limits, and executors. */
  runtime: Runtime;
  /** Key for the sender of this request; `undefined` rejects with 401. */
  keyResolver: ExpressKeyResolver;
}

/**
 * Provider-side Express middleware. It reads `{ "signal": "<json>" }` (or a
 * raw text body), resolves the sender key, and lets the runtime decide.
 * Authorization never happens here.
 */
export function providerMiddleware(
  options: ProviderMiddlewareOptions
): RequestHandler {
  const { runtime, keyResolver } = options;

  return async (request, response) => {
    const signal = extractSignal(request.body);
    if (signal === undefined) {
      response
        .status(400)
        .json({ outcome: "invalid_request", error: "invalid_request" });
      return;
    }

    let publicKey: Uint8Array | undefined;
    try {
      publicKey = await keyResolver(request);
    } catch {
      publicKey = undefined;
    }
    if (publicKey === undefined) {
      response
        .status(401)
        .json({ outcome: "unauthenticated", error: "unauthenticated" });
      return;
    }

    try {
      const decision = await runtime.submit(signal, publicKey);
      response.status(httpStatusFor(decision)).json(decision);
    } catch {
      response
        .status(500)
        .json({ outcome: "outcome_unknown", error: "outcome_unknown" });
    }
  };
}

function extractSignal(body: unknown): string | undefined {
  if (typeof body === "string") return body;
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return undefined;
  }
  const value = (body as Record<string, unknown>).signal;
  return typeof value === "string" ? value : undefined;
}
