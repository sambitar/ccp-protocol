import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseStrict } from "../src/parse.js";
import type { JsonValue } from "../src/json.js";
import { publicFromSeed } from "../src/crypto.js";
import { signDocument, signingBytes } from "../src/signing.js";

const path = fileURLToPath(
  new URL("../../../test-vectors/ed25519.json", import.meta.url)
);
const data = JSON.parse(readFileSync(path, "utf8"));

describe("signing vectors", () => {
  for (const vector of data.signing_vectors) {
    it(vector.id, () => {
      const value = parseStrict(vector.document);
      const bytes = signingBytes(value);
      expect(new TextDecoder().decode(bytes)).toBe(vector.signing_input);
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(
        vector.signing_input_sha256
      );
      const seed = Uint8Array.from(Buffer.from(vector.seed_hex, "hex"));
      expect(Buffer.from(publicFromSeed(seed)).toString("hex")).toBe(
        vector.public_key_hex
      );
      expect(
        signDocument(value as { [key: string]: JsonValue }, seed)
      ).toBe(vector.wire);
    });
  }
});
