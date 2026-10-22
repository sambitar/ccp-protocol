import { describe, expect, it } from "vitest";
import {
  IdentityError,
  admit,
  admittedGrant,
  admittedGrantId,
  buildAdmissionPolicy,
  buildIdentityDocument,
  identityDigest,
  policyDigest,
  verifyAdmissionPolicy,
  verifyIdentityDocument,
  type AdmissionRequest,
  type PolicyRule,
} from "../src/identity.js";
import { keyIdFromPublic, publicFromSeed } from "../src/crypto.js";

const SEED = Uint8Array.from({ length: 32 }, (_, index) => index);
const OTHER_SEED = Uint8Array.from({ length: 32 }, (_, index) => index + 32);
const IDENTITY = keyIdFromPublic(publicFromSeed(SEED));
const OTHER = keyIdFromPublic(publicFromSeed(OTHER_SEED));
const NOW = "2026-10-22T12:00:00Z";
const ISSUED = "2026-10-22T00:00:00Z";
const UNTIL = "2027-10-22T00:00:00Z";
const DIGEST = "sha256:" + "ab".repeat(32);
const OTHER_DIGEST = "sha256:" + "cd".repeat(32);

function document(overrides: Record<string, unknown> = {}): string {
  return buildIdentityDocument(
    {
      name: "Example Service",
      roles: ["provider"],
      endpoints: [
        {
          transport: "https",
          manifest: "https://example.com/manifest",
          signal: "https://example.com/ccp",
        },
      ],
      manifestDigest: DIGEST,
      policyDigest: DIGEST,
      issuedAt: ISSUED,
      expiresAt: UNTIL,
      ...overrides,
    },
    SEED
  );
}

function catchCode(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof IdentityError) return error.code;
    throw error;
  }
  throw new Error("expected an IdentityError");
}

const READ_RULE: PolicyRule = {
  id: "r-read",
  contacts: ["c-agent-1"],
  intents: ["files.search", "calendar.read"],
  risk: "read",
  limits: { calls_per_hour: 60 },
  confirmation: "none",
  expires_at: UNTIL,
};

const PAY_RULE: PolicyRule = {
  id: "r-pay",
  requesters: [OTHER],
  intents: ["payment.address.resolve"],
  risk: "disclose",
  destinations: ["wallet:acct-9"],
  confirmation: "none",
  expires_at: UNTIL,
};

function policy(rules: PolicyRule[] = [READ_RULE, PAY_RULE]): string {
  return buildAdmissionPolicy(
    {
      version: 1,
      default: "confirm",
      rules,
      issuedAt: ISSUED,
      expiresAt: UNTIL,
    },
    SEED
  );
}

function request(overrides: Partial<AdmissionRequest> = {}): AdmissionRequest {
  return {
    requesterKey: OTHER,
    contactId: "c-agent-1",
    intent: "files.search",
    risk: "read",
    now: NOW,
    ...overrides,
  };
}

describe("identity documents", () => {
  it("round-trips and derives the identity from the seed", () => {
    const verified = verifyIdentityDocument(document(), { now: NOW });
    expect(verified.identity).toBe(IDENTITY);
    expect(verified.name).toBe("Example Service");
    expect(verified.roles).toEqual(["provider"]);
    expect(verified.manifestDigest).toBe(DIGEST);
    expect(verified.endpoints).toHaveLength(1);
  });

  it("is self-certifying and deterministic", () => {
    expect(document()).toBe(document());
    expect(identityDigest(document())).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("rejects a tampered document", () => {
    const tampered = document().replace("Example Service", "Evil Service");
    expect(catchCode(() => verifyIdentityDocument(tampered, { now: NOW }))).toBe(
      "unauthenticated"
    );
  });

  it("reports a changed key as identity_changed", () => {
    expect(
      catchCode(() =>
        verifyIdentityDocument(document(), { now: NOW, expectedIdentity: OTHER })
      )
    ).toBe("identity_changed");
  });

  it("rejects expired and not-yet-valid documents", () => {
    expect(
      catchCode(() =>
        verifyIdentityDocument(
          document({ issuedAt: "2025-01-01T00:00:00Z", expiresAt: "2025-06-01T00:00:00Z" }),
          { now: NOW }
        )
      )
    ).toBe("identity_expired");
    expect(
      catchCode(() =>
        verifyIdentityDocument(
          document({ issuedAt: "2027-06-01T00:00:00Z", expiresAt: "2028-01-01T00:00:00Z" }),
          { now: NOW }
        )
      )
    ).toBe("identity_expired");
  });

  it("checks digest bindings", () => {
    expect(
      catchCode(() =>
        verifyIdentityDocument(document(), { now: NOW, manifestDigest: OTHER_DIGEST })
      )
    ).toBe("manifest_mismatch");
    expect(
      catchCode(() =>
        verifyIdentityDocument(document(), { now: NOW, policyDigest: OTHER_DIGEST })
      )
    ).toBe("policy_mismatch");
  });

  it("allows a 120 second clock skew", () => {
    const verified = verifyIdentityDocument(
      document({ issuedAt: "2026-10-22T12:01:00Z", expiresAt: UNTIL }),
      { now: NOW }
    );
    expect(verified.issuedAt).toBe("2026-10-22T12:01:00Z");
  });

  it("rejects an undocumented role", () => {
    expect(
      catchCode(() =>
        verifyIdentityDocument(document({ roles: ["provider", "admin"] }), { now: NOW })
      )
    ).toBe("invalid_request");
  });
});

describe("admission policies", () => {
  it("verifies a policy and exposes its rules", () => {
    const verified = verifyAdmissionPolicy(policy(), {
      now: NOW,
      expectedHost: IDENTITY,
    });
    expect(verified.host).toBe(IDENTITY);
    expect(verified.version).toBe(1);
    expect(verified.default).toBe("confirm");
    expect(verified.rules.map((rule) => rule.id)).toEqual(["r-read", "r-pay"]);
    expect(verified.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(policyDigest(policy())).toBe(verified.digest);
  });

  it("refuses a default that admits", () => {
    const wire = buildAdmissionPolicy(
      {
        version: 1,
        // @ts-expect-error -- the parser, not the type, must reject this
        default: "allow",
        rules: [READ_RULE],
        issuedAt: ISSUED,
        expiresAt: UNTIL,
      },
      SEED
    );
    expect(catchCode(() => verifyAdmissionPolicy(wire, { now: NOW }))).toBe(
      "invalid_request"
    );
  });

  it("refuses a rule that names nobody", () => {
    const wire = policy([{ ...READ_RULE, contacts: undefined }]);
    expect(catchCode(() => verifyAdmissionPolicy(wire, { now: NOW }))).toBe(
      "invalid_request"
    );
  });

  it("refuses write and irreversible risks", () => {
    const wire = policy([{ ...READ_RULE, risk: "write" as "read" }]);
    expect(catchCode(() => verifyAdmissionPolicy(wire, { now: NOW }))).toBe(
      "invalid_request"
    );
  });

  it("requires pinned destinations for disclose", () => {
    const wire = policy([{ ...PAY_RULE, destinations: undefined }]);
    expect(catchCode(() => verifyAdmissionPolicy(wire, { now: NOW }))).toBe(
      "invalid_request"
    );
  });

  it("reports an expired policy", () => {
    expect(
      catchCode(() => verifyAdmissionPolicy(policy(), { now: "2028-01-01T00:00:00Z" }))
    ).toBe("policy_expired");
  });
});

describe("admission", () => {
  const verified = verifyAdmissionPolicy(policy(), { now: NOW });

  it("admits a matching contact rule", () => {
    const result = admit(verified, request());
    expect(result).toEqual({
      decision: "allow",
      reason: "rule_matched",
      ruleId: "r-read",
    });
    const granted = admittedGrant(verified, request(), result);
    expect(granted).toMatchObject({
      intent: "files.search",
      limits: { calls_per_hour: 60 },
      expiresAt: UNTIL,
    });
    expect(granted!.id).toMatch(/^pg-[0-9a-f]{32}$/);
  });

  it("falls back to the default for an unknown contact", () => {
    expect(admit(verified, request({ contactId: "c-stranger" })).decision).toBe(
      "confirm"
    );
  });

  it("never admits a write", () => {
    expect(admit(verified, request({ risk: "write" })).decision).toBe("deny");
  });

  it("admits a disclose only to a pinned destination", () => {
    const base = {
      requesterKey: OTHER,
      intent: "payment.address.resolve",
      risk: "disclose" as const,
      now: NOW,
    };
    expect(admit(verified, { ...base, contactId: "c", destination: "wallet:acct-9" }).decision).toBe(
      "allow"
    );
    expect(admit(verified, { ...base, contactId: "c", destination: "wallet:acct-1" }).decision).toBe(
      "confirm"
    );
  });

  it("matches requester rules by key", () => {
    expect(
      admit(verified, {
        requesterKey: IDENTITY,
        contactId: "c",
        intent: "payment.address.resolve",
        risk: "disclose",
        destination: "wallet:acct-9",
        now: NOW,
      }).decision
    ).toBe("confirm");
  });

  it("returns no grant unless the decision was allow", () => {
    const result = admit(verified, request({ contactId: "c-stranger" }));
    expect(admittedGrant(verified, request(), result)).toBeUndefined();
  });

  it("gives a policy grant a deterministic id", () => {
    const first = admittedGrant(verified, request(), admit(verified, request()));
    const second = admittedGrant(verified, request(), admit(verified, request()));
    expect(first!.id).toBe(second!.id);
    expect(first!.id).toBe(admittedGrantId(verified, "r-read", request()));
  });

  it("refuses a revoked grant instead of re-creating it", () => {
    const id = admittedGrantId(verified, "r-read", request());
    const result = admit(verified, request(), { revoked: new Set([id]) });
    expect(result.decision).toBe("deny");
    expect(result.reason).toBe("grant_revoked");
    expect(admittedGrant(verified, request(), result)).toBeUndefined();
  });

  it("scopes revocation to one rule", () => {
    const id = admittedGrantId(verified, "r-read", request());
    const result = admit(
      verified,
      {
        requesterKey: OTHER,
        contactId: "c",
        intent: "payment.address.resolve",
        risk: "disclose",
        destination: "wallet:acct-9",
        now: NOW,
      },
      { revoked: new Set([id]) }
    );
    expect(result.decision).toBe("allow");
    expect(result.ruleId).toBe("r-pay");
  });

  it("changes the id when the policy changes", () => {
    const amended = verifyAdmissionPolicy(
      policy([{ ...READ_RULE, limits: { calls_per_hour: 30 } }]),
      { now: NOW }
    );
    expect(admittedGrantId(amended, "r-read", request())).not.toBe(
      admittedGrantId(verified, "r-read", request())
    );
  });
});
