import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseStrict } from "../src/parse.js";
import { serialize } from "../src/json.js";

const path = fileURLToPath(
  new URL("../../../test-vectors/canonical-json.json", import.meta.url)
);
const data = JSON.parse(readFileSync(path, "utf8"));

describe("canonical-json vectors", () => {
  for (const vector of data.vectors) {
    it(vector.id, () => {
      if (vector.expect_error) {
        expect(() => parseStrict(vector.document)).toThrow(
          new RegExp(vector.expect_error)
        );
      } else {
        expect(serialize(parseStrict(vector.document))).toBe(
          vector.expected_canonical
        );
      }
    });
  }
});
