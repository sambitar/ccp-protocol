import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  permissionCard,
  verifyManifest,
  verifySignal,
} from "../src/consumer.js";

const path = fileURLToPath(
  new URL("../../../test-vectors/ed25519.json", import.meta.url)
);
const data = JSON.parse(readFileSync(path, "utf8"));
const signed = data.signing_vectors;
const manifestWire = signed.find((v: any) => v.name === "sign a manifest").wire;
const signalWire = signed.find((v: any) => v.name === "sign a signal").wire;
const publicKey = Uint8Array.from(
  Buffer.from(signed[0].public_key_hex, "hex")
);
const providerId = signed[0].key_id;

describe("Consumer.verifyManifest", () => {
  it("verifies the signed manifest and derives its digest", () => {
    const result = verifyManifest(manifestWire);
    expect(result.providerId).toBe(providerId);
    expect(result.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("rejects a tampered manifest", () => {
    const tampered = manifestWire.replace("Example Service", "Evil Service");
    expect(() => verifyManifest(tampered)).toThrow(/unauthenticated/);
  });

  it("rejects a mismatched expected provider", () => {
    expect(() => verifyManifest(manifestWire, "key:ed25519:other")).toThrow(
      /unauthenticated/
    );
  });
});

describe("Consumer.verifySignal", () => {
  it("verifies a signed signal", () => {
    const result = verifySignal(signalWire, publicKey);
    expect(result.signal.request_id).toBe("req-00000001");
  });

  it("rejects a tampered signature", () => {
    const tampered = signalWire.replace(
      /"signature":"ed25519:[^"]+"/,
      '"signature":"ed25519:AAAA"'
    );
    expect(() => verifySignal(tampered, publicKey)).toThrow();
  });
});

describe("Consumer.permissionCard", () => {
  it("renders the §11.4 fields", () => {
    const verified = verifyManifest(manifestWire);
    const card = permissionCard(verified.manifest, "example.lookup", {
      providerName: "Example Service",
    });
    expect(card.who).toBe("Example Service");
    expect(card.what).toContain("Look up one item");
    expect(card.where).toContain("device");
    expect(card.egress).toContain("does not send");
    expect(card.recurrence).toBe("applies once");
  });
});
