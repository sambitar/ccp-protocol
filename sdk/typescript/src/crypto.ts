import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";

// @noble/ed25519 v2 needs an explicit SHA-512 for synchronous signing.
ed.etc.sha512Sync = (...messages: Uint8Array[]) =>
  sha512(ed.etc.concatBytes(...messages));

const KEY_PREFIX = "key:ed25519:";
const SIG_PREFIX = "ed25519:";

export function b64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text: string): Uint8Array {
  const base = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base + "=".repeat((4 - (base.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function keyIdFromPublic(raw: Uint8Array): string {
  return KEY_PREFIX + b64urlEncode(raw);
}

export function publicBytesFromKeyId(keyId: string): Uint8Array {
  if (!keyId.startsWith(KEY_PREFIX)) throw new Error("unsupported key id");
  return b64urlDecode(keyId.slice(KEY_PREFIX.length));
}

export function publicFromSeed(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  return ed.getPublicKey(seed);
}

export function sign(message: Uint8Array, seed: Uint8Array): string {
  return SIG_PREFIX + b64urlEncode(ed.sign(message, seed));
}

export function verify(
  message: Uint8Array,
  signatureField: string,
  publicKey: Uint8Array
): boolean {
  if (!signatureField.startsWith(SIG_PREFIX)) return false;
  const signature = b64urlDecode(signatureField.slice(SIG_PREFIX.length));
  return ed.verify(signature, message, publicKey);
}

export function sha256Hex(bytes: Uint8Array): string {
  return Array.from(sha256(bytes))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** `sha256:<hex>` over the given bytes. */
export function digestBytes(bytes: Uint8Array): string {
  return "sha256:" + sha256Hex(bytes);
}
