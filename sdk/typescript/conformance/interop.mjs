#!/usr/bin/env node
/**
 * Cross-language interop: sign a fixed manifest and signal, or verify the
 * other implementation's output.
 *
 * Usage:
 *   node conformance/interop.mjs generate <out.json>
 *   node conformance/interop.mjs verify <in.json>
 *
 * Requires `npm run build` first (the orchestrator does this).
 */
import { readFileSync, writeFileSync } from "node:fs";

import {
  Requester,
  keyIdFromPublic,
  parseStrict,
  publicFromSeed,
  sha256Hex,
  signingBytes,
  verifyManifest,
  verifySignal,
} from "../dist/index.js";

const PROVIDER_SEED = Uint8Array.from({ length: 32 }, (_, index) => index);
const REQUESTER_SEED = Uint8Array.from(
  { length: 32 },
  (_, index) => index + 32
);

const INTENTS = {
  "example.lookup": {
    description: "Lookup caf\u00e9 e\u0301 \u{1f600}",
    params_schema: "schema:example.lookup.params.v1",
    result_schema: "schema:example.lookup.result.v1",
    required_capabilities: ["store.read"],
    placement: "local",
    data_egress: { network: false, fields: [] },
    suggested_limits: { calls_per_hour: 10 },
    confirmation: "per_action",
  },
};

const PARAMS = {
  item_id: "caf\u00e9",
  note: "e\u0301 \u{1f600}",
  count: 18446744073709551616n,
};

function generate() {
  const provider = new Requester(PROVIDER_SEED);
  const requester = new Requester(REQUESTER_SEED);

  const manifestWire = provider.manifest({
    provider: { id: provider.keyId, name: "Example Service \u2014 \u4f8b" },
    version: 1,
    intents: INTENTS,
  });
  const digest = verifyManifest(manifestWire).digest;

  const signalWire = requester.signal({
    requestId: "interop-1",
    grantDigest: digest,
    intent: "example.lookup",
    params: PARAMS,
    issuedAt: "2026-10-22T12:00:00Z",
    expiresAt: "2026-10-22T12:01:00Z",
  });

  return {
    manifest_wire: manifestWire,
    manifest_digest: digest,
    signal_wire: signalWire,
    signal_signing_sha256: sha256Hex(signingBytes(parseStrict(signalWire))),
  };
}

function verify(data) {
  const providerPublic = publicFromSeed(PROVIDER_SEED);
  const requesterPublic = publicFromSeed(REQUESTER_SEED);

  const manifest = verifyManifest(
    data.manifest_wire,
    keyIdFromPublic(providerPublic)
  );
  if (manifest.digest !== data.manifest_digest) {
    throw new Error("manifest digest mismatch");
  }

  verifySignal(data.signal_wire, requesterPublic);

  const signingHash = sha256Hex(signingBytes(parseStrict(data.signal_wire)));
  if (signingHash !== data.signal_signing_sha256) {
    throw new Error("signal signing hash mismatch");
  }
}

function main() {
  const [mode, path] = process.argv.slice(2);
  if (!mode || !path) {
    console.error("usage: node conformance/interop.mjs <generate|verify> <path>");
    process.exit(2);
  }
  if (mode === "generate") {
    writeFileSync(path, JSON.stringify(generate(), null, 2) + "\n");
  } else if (mode === "verify") {
    verify(JSON.parse(readFileSync(path, "utf8")));
  } else {
    console.error(`unknown mode: ${mode}`);
    process.exit(2);
  }
  console.log("ok");
}

try {
  main();
} catch (error) {
  console.error(String(error));
  process.exit(1);
}
