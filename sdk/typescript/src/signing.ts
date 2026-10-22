import type { JsonValue } from "./json.js";
import { serialize } from "./json.js";
import { sign } from "./crypto.js";

function withoutSignature(value: JsonValue): JsonValue {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return value;
  }
  const copy: { [key: string]: JsonValue } = { ...value };
  delete copy.signature;
  return copy;
}

/** Canonical signing bytes: the value with `signature` excluded. */
export function signingBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(serialize(withoutSignature(value)));
}

/** Return the canonical wire form of `value`, signed by `seed`. */
export function signDocument(
  value: { [key: string]: JsonValue },
  seed: Uint8Array
): string {
  const copy: { [key: string]: JsonValue } = { ...value };
  delete copy.signature;
  copy.signature = sign(signingBytes(copy), seed);
  return serialize(copy);
}
