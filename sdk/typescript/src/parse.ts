import type { JsonValue } from "./json.js";
import { assertWellFormed } from "./json.js";

/**
 * Parse JSON with the CCP profile's strictness:
 * - non-negative integers only (as `bigint`), no floats/exponents/negatives;
 * - duplicate keys rejected;
 * - NaN/Infinity and trailing content rejected.
 */
export function parseStrict(text: string): JsonValue {
  let i = 0;
  const fail = (code: string): never => {
    throw new SyntaxError(code);
  };
  const skipWs = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const expect = (token: string) => {
    if (text.slice(i, i + token.length) !== token) fail("malformed");
    i += token.length;
  };

  const parseString = (): string => {
    i++; // opening quote
    let out = "";
    while (i < text.length) {
      const c = text[i++];
      if (c === '"') {
        assertWellFormed(out);
        return out;
      }
      if (c === "\\") {
        const e = text[i++];
        if (e === '"') out += '"';
        else if (e === "\\") out += "\\";
        else if (e === "/") out += "/";
        else if (e === "b") out += "\b";
        else if (e === "f") out += "\f";
        else if (e === "n") out += "\n";
        else if (e === "r") out += "\r";
        else if (e === "t") out += "\t";
        else if (e === "u") {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("malformed");
          const code = parseInt(hex, 16);
          i += 4;
          if (code >= 0xd800 && code <= 0xdbff) {
            if (text[i] !== "\\" || text[i + 1] !== "u") fail("malformed");
            const lowHex = text.slice(i + 2, i + 6);
            if (!/^[0-9a-fA-F]{4}$/.test(lowHex)) fail("malformed");
            const low = parseInt(lowHex, 16);
            if (low < 0xdc00 || low > 0xdfff) fail("malformed");
            i += 6;
            out += String.fromCodePoint(
              0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00)
            );
          } else if (code >= 0xdc00 && code <= 0xdfff) {
            fail("malformed");
          } else {
            out += String.fromCodePoint(code);
          }
        } else {
          fail("malformed");
        }
      } else if (c.charCodeAt(0) < 0x20) {
        fail("malformed");
      } else {
        out += c;
      }
    }
    return fail("malformed");
  };

  const parseNumber = (): bigint => {
    if (text[i] === "-") fail("negative");
    const start = i;
    while (i < text.length && text[i] >= "0" && text[i] <= "9") i++;
    if (i === start) fail("malformed");
    if (text[i] === "." || text[i] === "e" || text[i] === "E") fail("float");
    const digits = text.slice(start, i);
    if (digits.length > 1 && digits[0] === "0") fail("malformed");
    return BigInt(digits);
  };

  const parseObject = (): { [key: string]: JsonValue } => {
    i++; // {
    const obj: { [key: string]: JsonValue } = Object.create(null);
    const seen = new Set<string>();
    skipWs();
    if (text[i] === "}") {
      i++;
      return obj;
    }
    for (;;) {
      skipWs();
      if (text[i] !== '"') fail("malformed");
      const key = parseString();
      const folded = key.normalize("NFC");
      if (seen.has(folded)) fail("duplicate");
      seen.add(folded);
      skipWs();
      expect(":");
      obj[key] = parseValue();
      skipWs();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "}") {
        i++;
        return obj;
      }
      fail("malformed");
    }
  };

  const parseArray = (): JsonValue[] => {
    i++; // [
    const arr: JsonValue[] = [];
    skipWs();
    if (text[i] === "]") {
      i++;
      return arr;
    }
    for (;;) {
      arr.push(parseValue());
      skipWs();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "]") {
        i++;
        return arr;
      }
      fail("malformed");
    }
  };

  const parseValue = (): JsonValue => {
    skipWs();
    const c = text[i];
    if (c === "{") return parseObject();
    if (c === "[") return parseArray();
    if (c === '"') return parseString();
    if (c === "N" || c === "I") return fail("constant");
    if (c === "-") {
      if (text.startsWith("-Infinity", i)) return fail("constant");
      return fail("negative");
    }
    if (c === "t") {
      expect("true");
      return true;
    }
    if (c === "f") {
      expect("false");
      return false;
    }
    if (c === "n") {
      expect("null");
      return null;
    }
    if (c >= "0" && c <= "9") return parseNumber();
    return fail("malformed");
  };

  const result = parseValue();
  skipWs();
  if (i !== text.length) fail("malformed");
  return result;
}
