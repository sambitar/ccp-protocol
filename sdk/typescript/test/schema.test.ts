import { describe, expect, it } from "vitest";
import { isValid } from "../src/schema.js";

const schema = {
  type: "object",
  properties: { item_id: { type: "string" } },
  required: ["item_id"],
  additionalProperties: false,
};

describe("schema subset", () => {
  it("accepts a valid object", () => {
    expect(isValid({ item_id: "x" }, schema)).toBe(true);
  });

  it("rejects a missing required field", () => {
    expect(isValid({}, schema)).toBe(false);
  });

  it("rejects a wrong type", () => {
    expect(isValid({ item_id: 1n }, schema)).toBe(false);
  });

  it("rejects additional properties", () => {
    expect(isValid({ item_id: "x", extra: 1n }, schema)).toBe(false);
  });

  it("accepts integer numbers and rejects non-integers", () => {
    expect(isValid(5, { type: "integer" })).toBe(true);
    expect(isValid(1.5, { type: "integer" })).toBe(false);
  });
});
