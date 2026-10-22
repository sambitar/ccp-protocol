import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  IdentityError,
  admit,
  verifyAdmissionPolicy,
  verifyIdentityDocument,
} from "../src/identity.js";

function load(name: string): any {
  const path = fileURLToPath(
    new URL(`../../../test-vectors/v4/${name}`, import.meta.url)
  );
  return JSON.parse(readFileSync(path, "utf8"));
}

function code(run: () => unknown): string {
  try {
    run();
    return "valid";
  } catch (error) {
    if (error instanceof IdentityError) return error.code;
    throw error;
  }
}

const data = load("identity.json");

describe("identity v4 vectors", () => {
  for (const vector of data.identities) {
    it(vector.id, () => {
      const got = code(() =>
        verifyIdentityDocument(vector.document, {
          now: vector.now,
          expectedIdentity: vector.expected_identity,
          manifestDigest: vector.manifest_digest,
          policyDigest: vector.policy_digest,
        })
      );
      expect(got).toBe(vector.expected);
    });
  }
});

describe("policy v4 vectors", () => {
  for (const vector of data.policies) {
    it(vector.id, () => {
      const got = code(() =>
        verifyAdmissionPolicy(vector.document, {
          now: vector.now,
          expectedHost: vector.expected_host,
        })
      );
      expect(got).toBe(vector.expected);
    });
  }
});

describe("admission v4 vectors", () => {
  for (const vector of data.admissions) {
    it(vector.id, () => {
      const policy = verifyAdmissionPolicy(vector.policy, {
        now: vector.verify_now,
      });
      const result = admit(
        policy,
        {
          requesterKey: vector.request.requester_key,
          contactId: vector.request.contact_id,
          intent: vector.request.intent,
          risk: vector.request.risk,
          destination: vector.request.destination,
          now: vector.request.now,
        },
        { revoked: new Set<string>(vector.revoked ?? []) }
      );
      expect(result.decision).toBe(vector.expected);
      if (vector.expected_rule !== undefined) {
        expect(result.ruleId).toBe(vector.expected_rule);
      }
      if (vector.expected_reason !== undefined) {
        expect(result.reason).toBe(vector.expected_reason);
      }
    });
  }
});
