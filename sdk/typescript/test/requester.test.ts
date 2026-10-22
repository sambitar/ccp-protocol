import { describe, expect, it } from "vitest";
import { parseStrict } from "../src/parse.js";
import { signingBytes } from "../src/signing.js";
import { keyIdFromPublic, publicFromSeed, verify } from "../src/crypto.js";
import {
  Requester,
  buildManifest,
  buildSignal,
  signManifest,
  signSignal,
} from "../src/requester.js";

const SEED = Uint8Array.from({ length: 32 }, (_, index) => index);
const PROVIDER_ID = keyIdFromPublic(publicFromSeed(SEED));

const INTENTS = {
  "example.lookup": {
    params_schema: "schema:example.lookup.params.v1",
    result_schema: "schema:example.lookup.result.v1",
    required_capabilities: ["store.read"],
    confirmation: "grant-policy",
  },
};

const SIGNAL_INPUT = {
  requestId: "req-1",
  grantDigest: "sha256:abc",
  intent: "example.lookup",
  params: { item_id: "x" },
  issuedAt: "2026-10-22T12:00:00Z",
  expiresAt: "2026-10-22T12:01:00Z",
};

describe("Requester", () => {
  it("builds a manifest with a default ccp", () => {
    const manifest = buildManifest({
      provider: { id: PROVIDER_ID, name: "Example" },
      version: 1,
      intents: INTENTS,
    });
    expect(manifest.ccp).toBe("0.5-draft");
    expect(manifest.version).toBe(1);
    expect(manifest.provider).toEqual({ id: PROVIDER_ID, name: "Example" });
  });

  it("signs a manifest that verifies against the provider key", () => {
    const wire = signManifest(
      {
        provider: { id: PROVIDER_ID, name: "Example" },
        version: 1,
        intents: INTENTS,
      },
      SEED
    );
    const data = parseStrict(wire) as any;
    expect(verify(signingBytes(data), data.signature, publicFromSeed(SEED))).toBe(
      true
    );
    expect(data.provider.id).toBe(PROVIDER_ID);
  });

  it("builds a signal with snake_case wire fields", () => {
    const signal = buildSignal(SIGNAL_INPUT);
    expect(signal.ccp).toBe("0.5-draft");
    expect(signal.request_id).toBe("req-1");
    expect(signal.grant_digest).toBe("sha256:abc");
  });

  it("signs a signal that verifies", () => {
    const wire = signSignal(SIGNAL_INPUT, SEED);
    const data = parseStrict(wire) as any;
    expect(data.request_id).toBe("req-1");
    expect(verify(signingBytes(data), data.signature, publicFromSeed(SEED))).toBe(
      true
    );
  });

  it("exposes a Requester class", () => {
    const requester = new Requester(SEED);
    const wire = requester.signal({ ...SIGNAL_INPUT, requestId: "req-2" });
    expect((parseStrict(wire) as any).request_id).toBe("req-2");
  });
});
