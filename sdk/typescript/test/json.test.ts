import { describe, expect, it } from "vitest";
import { serialize } from "../src/json.js";

describe("canonical serialize", () => {
  it("sorts keys by code point and appends signature last", () => {
    expect(serialize({ z: 1n, a: 2n, signature: "ed25519:x" })).toBe(
      '{"a":2,"z":1,"signature":"ed25519:x"}'
    );
  });

  it("normalizes NFC and applies minimal escaping", () => {
    expect(serialize({ a: "e\u0301" })).toBe('{"a":"é"}');
    expect(serialize({ a: "line\nbreak" })).toBe('{"a":"line\\nbreak"}');
    expect(serialize({ a: 'x"y\\z' })).toBe('{"a":"x\\"y\\\\z"}');
  });

  it("preserves array order and scalar types", () => {
    expect(serialize([3n, 2n, 1n])).toBe("[3,2,1]");
    expect(serialize({ a: true, b: false, c: null })).toBe(
      '{"a":true,"b":false,"c":null}'
    );
  });

  it("sorts astral-plane keys by code point, not UTF-16 unit", () => {
    expect(serialize({ "\uFFFF": 1n, "\u{1F600}": 2n })).toBe(
      '{"\uFFFF":1,"😀":2}'
    );
  });

  it("accepts safe non-negative integers as number", () => {
    expect(serialize({ n: 5 })).toBe('{"n":5}');
  });

  it("rejects number floats, negatives, and unsafe integers", () => {
    expect(() => serialize({ n: 1.5 })).toThrow(/float/);
    expect(() => serialize({ n: -1 })).toThrow(/negative/);
    expect(() => serialize({ n: 1e20 })).toThrow(/float/);
  });
});
