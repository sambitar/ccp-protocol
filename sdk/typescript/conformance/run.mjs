#!/usr/bin/env node
/**
 * Language-neutral conformance harness for the TypeScript SDK.
 *
 * Usage: node conformance/run.mjs <vectors-dir>
 *
 * Reads whichever of canonical-json.json and validation.json exist in the
 * directory, prints a JSON summary, and exits 1 if any case fails. Requires
 * `npm run build` first (the orchestrator does this).
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { decide, parseStrict, serialize } from "../dist/index.js";
import {
  admit,
  validateHostProfile,
  verifyAdmissionPolicy,
  verifyIdentityDocument,
} from "../dist/index.js";

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

function load(directory, name) {
  return JSON.parse(readFileSync(join(directory, name), "utf8"));
}

function runCanonical(data) {
  const failures = [];
  for (const vector of data.vectors) {
    let got;
    try {
      got = serialize(parseStrict(vector.document));
    } catch (error) {
      got = `error:${error.message}`;
    }
    const expected = vector.expect_error
      ? `error:${vector.expect_error}`
      : vector.expected_canonical;
    if (got !== expected) {
      failures.push({ id: vector.id, expected, got });
    }
  }
  return {
    passed: data.vectors.length - failures.length,
    failed: failures.length,
    failures,
  };
}

function runValidation(data) {
  const failures = [];
  for (const vector of data.vectors) {
    let got;
    try {
      got = decide({
        grant: vector.grant,
        signal: vector.signal,
        signer: vector.signer,
        now: vector.context.now,
        seen: new Set(vector.context.seen),
        counters: vector.context.counters,
        intentSpec: INTENT_SPEC,
        paramsSchema: PARAMS_SCHEMA,
      });
    } catch (error) {
      got = `error:${error.message}`;
    }
    if (got !== vector.expected) {
      failures.push({ id: vector.id, expected: vector.expected, got });
    }
  }
  return {
    passed: data.vectors.length - failures.length,
    failed: failures.length,
    failures,
  };
}

function codeOf(error) {
  if (error && typeof error === "object" && "code" in error) {
    return error.code;
  }
  return `error:${error instanceof Error ? error.message : error}`;
}

function summarise(total, failures) {
  return { passed: total - failures.length, failed: failures.length, failures };
}

function runIdentities(data) {
  const failures = [];
  for (const vector of data.identities) {
    let got;
    try {
      verifyIdentityDocument(vector.document, {
        now: vector.now,
        expectedIdentity: vector.expected_identity,
        manifestDigest: vector.manifest_digest,
        policyDigest: vector.policy_digest,
      });
      got = "valid";
    } catch (error) {
      got = codeOf(error);
    }
    if (got !== vector.expected) {
      failures.push({ id: vector.id, expected: vector.expected, got });
    }
  }
  return summarise(data.identities.length, failures);
}

function runPolicies(data) {
  const failures = [];
  for (const vector of data.policies) {
    let got;
    try {
      verifyAdmissionPolicy(vector.document, {
        now: vector.now,
        expectedHost: vector.expected_host,
      });
      got = "valid";
    } catch (error) {
      got = codeOf(error);
    }
    if (got !== vector.expected) {
      failures.push({ id: vector.id, expected: vector.expected, got });
    }
  }
  return summarise(data.policies.length, failures);
}

function runAdmissions(data) {
  const failures = [];
  for (const vector of data.admissions) {
    let got;
    try {
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
        { revoked: new Set(vector.revoked ?? []) }
      );
      got =
        vector.expected_rule === undefined
          ? result.decision
          : `${result.decision}:${result.ruleId}`;
      if (vector.expected_reason !== undefined) {
        got += `:${result.reason}`;
      }
    } catch (error) {
      got = codeOf(error);
    }
    let expected =
      vector.expected_rule === undefined
        ? vector.expected
        : `${vector.expected}:${vector.expected_rule}`;
    if (vector.expected_reason !== undefined) {
      expected += `:${vector.expected_reason}`;
    }
    if (got !== expected) {
      failures.push({ id: vector.id, expected, got });
    }
  }
  return summarise(data.admissions.length, failures);
}

function runHosts(data) {
  const failures = [];
  for (const vector of data.vectors) {
    let got;
    try {
      validateHostProfile(vector.host, vector.profile);
      got = "valid";
    } catch (error) {
      got = codeOf(error);
    }
    if (got !== vector.expected) {
      failures.push({ id: vector.id, expected: vector.expected, got });
    }
  }
  return summarise(data.vectors.length, failures);
}

function main() {
  const directory = process.argv[2];
  if (!directory) {
    console.error("usage: node conformance/run.mjs <vectors-dir>");
    process.exit(2);
  }

  const summary = {};
  if (existsSync(join(directory, "canonical-json.json"))) {
    summary["canonical-json"] = runCanonical(
      load(directory, "canonical-json.json")
    );
  }
  if (existsSync(join(directory, "validation.json"))) {
    summary.validation = runValidation(load(directory, "validation.json"));
  }
  if (existsSync(join(directory, "identity.json"))) {
    const data = load(directory, "identity.json");
    summary.identity = runIdentities(data);
    summary.policy = runPolicies(data);
    summary.admission = runAdmissions(data);
  }
  if (existsSync(join(directory, "hosts.json"))) {
    summary.hosts = runHosts(load(directory, "hosts.json"));
  }

  console.log(JSON.stringify(summary, null, 2));
  const failed = Object.values(summary).reduce(
    (total, entry) => total + entry.failed,
    0
  );
  process.exitCode = failed === 0 ? 0 : 1;
}

main();
