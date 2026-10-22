export type JsonValue =
  | null
  | boolean
  | string
  | bigint
  | number
  | JsonValue[]
  | { [key: string]: JsonValue };

const SHORT: Record<string, string> = {
  "\b": "\\b",
  "\f": "\\f",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

/** Reject strings that are not valid Unicode scalar sequences (lone surrogates). */
export function assertWellFormed(text: string): void {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("malformed");
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error("malformed");
    }
  }
}

export function quote(value: string): string {
  assertWellFormed(value);
  const s = value.normalize("NFC");
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (SHORT[ch]) out += SHORT[ch];
    else if (code < 0x20) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

function compareCodePoint(a: string, b: string): number {
  const aa = Array.from(a);
  const bb = Array.from(b);
  const n = Math.min(aa.length, bb.length);
  for (let i = 0; i < n; i++) {
    const diff = aa[i].codePointAt(0)! - bb[i].codePointAt(0)!;
    if (diff !== 0) return diff;
  }
  return aa.length - bb.length;
}

export function serialize(value: JsonValue, topLevel = true): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return quote(value);
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error("negative");
    return value.toString();
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("float");
    if (value < 0) throw new Error("negative");
    if (!Number.isSafeInteger(value)) throw new Error("float");
    return value.toString();
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => serialize(item, false)).join(",") + "]";
  }
  if (typeof value === "object") {
    const regular = Object.keys(value).filter(
      (key) => !(topLevel && key === "signature")
    );
    const folded = new Map<string, JsonValue>();
    for (const key of regular) {
      const nfc = key.normalize("NFC");
      if (folded.has(nfc)) throw new Error("duplicate");
      folded.set(nfc, value[key]);
    }
    const keys = [...folded.keys()].sort(compareCodePoint);
    const parts = keys.map(
      (key) => quote(key) + ":" + serialize(folded.get(key)!, false)
    );
    if (topLevel && "signature" in value) {
      parts.push(quote("signature") + ":" + serialize(value.signature, false));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new TypeError("unsupported type");
}
