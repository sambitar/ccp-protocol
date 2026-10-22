import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseStrict } from "../src/parse.js";
import { serialize } from "../src/json.js";
import { decide } from "../src/decision.js";

function load(name: string): any {
  const path = fileURLToPath(
    new URL(`../../../test-vectors/v3/${name}`, import.meta.url)
  );
  return JSON.parse(readFileSync(path, "utf8"));
}

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

describe("canonical v3 vectors", () => {
  for (const vector of load("canonical-json.json").vectors) {
    it(vector.id, () => {
      if (vector.expect_error !== undefined) {
        expect(() => serialize(parseStrict(vector.document))).toThrow(
          vector.expect_error
        );
      } else {
        expect(serialize(parseStrict(vector.document))).toBe(
          vector.expected_canonical
        );
      }
    });
  }
});

describe("validation v3 vectors", () => {
  for (const vector of load("validation.json").vectors) {
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
