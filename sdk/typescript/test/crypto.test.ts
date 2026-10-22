import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  keyIdFromPublic,
  publicBytesFromKeyId,
  publicFromSeed,
  sign,
  verify,
} from "../src/crypto.js";

const path = fileURLToPath(
  new URL("../../../test-vectors/ed25519.json", import.meta.url)
);
const data = JSON.parse(readFileSync(path, "utf8"));

describe("Ed25519 known-answer vectors", () => {
  for (const vector of data.kat_vectors) {
    it(vector.id, () => {
      const seed = Uint8Array.from(Buffer.from(vector.secret_key_hex, "hex"));
      const pub = publicFromSeed(seed);
      expect(Buffer.from(pub).toString("hex")).toBe(vector.public_key_hex);
      expect(keyIdFromPublic(pub)).toBe(vector.key_id);
      const message = Uint8Array.from(
        Buffer.from(vector.message_hex, "hex")
      );
      expect(sign(message, seed)).toBe(vector.signature_field);
      expect(verify(message, vector.signature_field, pub)).toBe(true);
      expect(
        Buffer.from(publicBytesFromKeyId(vector.key_id)).toString("hex")
      ).toBe(vector.public_key_hex);
    });
  }
});
