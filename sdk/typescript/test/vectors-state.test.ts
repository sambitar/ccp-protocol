import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { nextState } from "../src/state-machine.js";

const path = fileURLToPath(
  new URL("../../../test-vectors/state-machine.json", import.meta.url)
);
const data = JSON.parse(readFileSync(path, "utf8"));

describe("state-machine vectors", () => {
  for (const vector of data.vectors) {
    it(vector.id, () => {
      const from = vector.from === "start" ? null : vector.from;
      expect(nextState(from, vector.event)).toBe(vector.to);
    });
  }
});
