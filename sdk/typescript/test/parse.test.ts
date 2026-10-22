import { describe, expect, it } from "vitest";
import { parseStrict } from "../src/parse.js";

describe("parseStrict", () => {
  it("parses integers as bigint (no precision loss)", () => {
    expect(parseStrict('{"a":12345678901234567890}')).toEqual({
      a: 12345678901234567890n,
    });
  });

  it("rejects duplicate keys", () => {
    expect(() => parseStrict('{"a":1,"a":2}')).toThrow(/duplicate/);
  });

  it("rejects floats, exponents, negatives, leading zeros", () => {
    expect(() => parseStrict('{"a":1.0}')).toThrow(/float/);
    expect(() => parseStrict('{"a":1e3}')).toThrow(/float/);
    expect(() => parseStrict('{"a":-1}')).toThrow(/negative/);
    expect(() => parseStrict('{"a":01}')).toThrow(/malformed/);
  });

  it("rejects NaN and trailing garbage", () => {
    expect(() => parseStrict('{"a":NaN}')).toThrow(/constant/);
    expect(() => parseStrict("{} x")).toThrow(/malformed/);
  });

  it("decodes escapes and surrogate pairs", () => {
    expect(parseStrict('"a\\nb"')).toBe("a\nb");
    expect(parseStrict('"\\uD83D\\uDE00"')).toBe("😀");
  });
});
