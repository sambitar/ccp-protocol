import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { decide } from "../src/decision.js";

const path = fileURLToPath(
  new URL("../../../test-vectors/validation.json", import.meta.url)
);
const data = JSON.parse(readFileSync(path, "utf8"));

const INTENT_SPEC = {
  required_capabilities: ["store.read"],
  confirmation: "grant-policy",
};
const PARAMS_SCHEMA = {
  type: "object",
  properties: { item_id: { type: "string" } },
  required: ["item_id"],
  additionalProperties: false,
};

describe("validation vectors", () => {
  for (const vector of data.vectors) {
    it(vector.id, () => {
      const result = decide({
        grant: vector.grant,
        signal: vector.signal,
        signer: vector.signer,
        now: vector.context.now,
        seen: new Set<string>(vector.context.seen),
        counters: vector.context.counters,
        intentSpec: INTENT_SPEC,
        paramsSchema: PARAMS_SCHEMA,
      });
      expect(result).toBe(vector.expected);
    });
  }
});
