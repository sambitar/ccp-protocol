import { describe, expect, it } from "vitest";
import { decide } from "../src/decision.js";
import { serialize } from "../src/json.js";
import type { JsonValue } from "../src/json.js";
import { parseStrict } from "../src/parse.js";
import { isValid } from "../src/schema.js";

function mulberry32(seed: number): () => number {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const STRINGS = [
  "a",
  "Z",
  "0",
  " ",
  "\u00e9",
  "e\u0301",
  "\u{1f600}",
  "\u0000",
  "\u001f",
  '"',
  "\\",
  "/",
  "~",
  "例",
];

const ERROR_CODES = new Set([
  "malformed",
  "duplicate",
  "negative",
  "float",
  "constant",
]);

function randomString(rand: () => number, maximum = 8): string {
  const length = Math.floor(rand() * (maximum + 1));
  let out = "";
  for (let index = 0; index < length; index++) {
    out += STRINGS[Math.floor(rand() * STRINGS.length)];
  }
  return out;
}

function randomValue(rand: () => number, depth = 0): JsonValue {
  const pick = Math.floor(rand() * (depth >= 3 ? 4 : 6));
  switch (pick) {
    case 0:
      return null;
    case 1:
      return rand() < 0.5;
    case 2:
      return rand() < 0.1
        ? BigInt("18446744073709551616")
        : BigInt(Math.floor(rand() * 1000000));
    case 3:
      return randomString(rand);
    case 4: {
      const length = Math.floor(rand() * 4);
      return Array.from({ length }, () => randomValue(rand, depth + 1));
    }
    default: {
      const entries: { [key: string]: JsonValue } = Object.create(null);
      const count = Math.floor(rand() * 4);
      for (let index = 0; index < count; index++) {
        entries[`${randomString(rand, 4)}${index}`] = randomValue(rand, depth + 1);
      }
      return entries;
    }
  }
}

const BASE_GRANT = {
  id: "g-1",
  requester_key: "key:ed25519:requester",
  contact_id: "c-1",
  manifest_digest: "sha256:digest",
  manifest_version: 1,
  intents: ["example.lookup"],
  limits: { calls_per_hour: 10 },
  created_at: "2026-10-22T10:00:00Z",
  expires_at: "2026-10-22T13:00:00Z",
  confirmation: { "example.lookup": "none" },
  capabilities: ["store.read"],
  placement: ["local"],
  egress: { network: false },
  state: "active",
  state_reason: null,
};

const BASE_SIGNAL = {
  ccp: "0.5-draft",
  request_id: "req-1",
  grant_digest: "sha256:digest",
  intent: "example.lookup",
  params: { item_id: "item-123" },
  issued_at: "2026-10-22T12:00:00Z",
  expires_at: "2026-10-22T12:01:00Z",
};

const INTENT_SPEC = {
  required_capabilities: ["store.read"],
  confirmation: "grant-policy",
};
const PARAMS_SCHEMA = {
  type: "object",
  properties: { item_id: { type: "string" } },
  required: ["item_id"],
  additionalProperties: false,
};

const OUTCOMES = new Set([
  "authorized",
  "confirmation_required",
  "invalid_request",
  "unauthenticated",
  "no_matching_grant",
  "intent_not_allowed",
  "grant_expired",
  "grant_revoked",
  "grant_paused",
  "grant_suspended",
  "request_expired",
  "replay_detected",
  "limit_exceeded",
  "capability_unavailable",
]);

describe("canonical properties", () => {
  it("round-trips and is idempotent", () => {
    const rand = mulberry32(20261022);
    for (let index = 0; index < 300; index++) {
      const value = randomValue(rand);
      const canonical = serialize(value);
      const parsed = parseStrict(canonical);
      expect(serialize(parsed)).toBe(canonical);
    }
  });

  it("never throws an unexpected error on random text", () => {
    const rand = mulberry32(7);
    const pool = [
      "{", "}", "[", "]", '"', "\\", ":", ",", "0", "1", "-", ".", "e",
      "E", "N", "I", "t", "f", "n", "u", "a", " ", "\n", "\t", "é", "😀",
      "\u0000",
    ];
    for (let index = 0; index < 300; index++) {
      const length = Math.floor(rand() * 20);
      let text = "";
      for (let position = 0; position < length; position++) {
        text += pool[Math.floor(rand() * pool.length)];
      }
      try {
        const canonical = serialize(parseStrict(text));
        expect(serialize(parseStrict(canonical))).toBe(canonical);
      } catch (error) {
        expect(ERROR_CODES.has((error as Error).message)).toBe(true);
      }
    }
  });

  it("counts string length in code points", () => {
    expect(
      isValid("😀", { type: "string", minLength: 1, maxLength: 1 })
    ).toBe(true);
  });
});

describe("decision properties", () => {
  it("is deterministic and returns a known outcome", () => {
    const rand = mulberry32(99);
    const states = ["active", "paused", "suspended", "revoked", "expired"];
    const times = [
      "2026-10-22T11:00:00Z",
      "2026-10-22T12:00:30Z",
      "2026-10-22T13:00:00Z",
    ];
    for (let index = 0; index < 300; index++) {
      const grant = {
        ...BASE_GRANT,
        state: states[Math.floor(rand() * states.length)],
        expires_at: times[Math.floor(rand() * times.length)],
        limits: { calls_per_hour: Math.floor(rand() * 15) },
      };
      const signal = {
        ...BASE_SIGNAL,
        expires_at: times[Math.floor(rand() * times.length)],
        params: rand() < 0.2 ? {} : { item_id: "item-123" },
        intent: rand() < 0.1 ? "files.search" : "example.lookup",
      };
      const seen =
        rand() < 0.2 ? new Set<string>(["req-1"]) : new Set<string>();
      const counters = { calls_per_hour: Math.floor(rand() * 15) };
      const signer =
        rand() < 0.1 ? "key:ed25519:other" : BASE_GRANT.requester_key;
      const now = times[Math.floor(rand() * times.length)];

      const context = {
        grant,
        signal,
        signer,
        now,
        seen,
        counters,
        intentSpec: INTENT_SPEC,
        paramsSchema: PARAMS_SCHEMA,
      };
      const first = decide(context);
      const second = decide({ ...context, seen: new Set(seen) });
      expect(second).toBe(first);
      expect(OUTCOMES.has(first)).toBe(true);
    }
  });
});
