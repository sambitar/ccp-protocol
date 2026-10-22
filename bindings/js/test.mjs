/**
 * Run the frozen v1, v2, and v3 vectors through the WASM kernel.
 *
 * Usage: node bindings/js/test.mjs
 * Requires: cargo build --release --target wasm32-unknown-unknown
 */
import { readFile } from "node:fs/promises";

import { loadKernel } from "./index.mjs";

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

async function loadJson(relative) {
  const path = new URL(`../../test-vectors/${relative}`, import.meta.url);
  return JSON.parse(await readFile(path, "utf8"));
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const suites = [];
function suite(name, vectors, check) {
  let failed = 0;
  for (const vector of vectors) {
    try {
      check(vector);
    } catch (error) {
      failed += 1;
      console.error(`FAIL ${vector.id}: ${error.message}`);
    }
  }
  suites.push({ name, passed: vectors.length - failed, total: vectors.length });
}

function envelope(value) {
  return JSON.stringify(value);
}

const kernel = await loadKernel();

const canonicalV1 = await loadJson("canonical-json.json");
const canonicalV2 = await loadJson("v2/canonical-json.json");
const canonicalV3 = await loadJson("v3/canonical-json.json");
const validationV1 = await loadJson("validation.json");
const validationV2 = await loadJson("v2/validation.json");
const validationV3 = await loadJson("v3/validation.json");
const stateMachine = await loadJson("state-machine.json");
const ed25519 = await loadJson("ed25519.json");

function canonicalCheck(vector) {
  const { result } = kernel.canonicalize(vector.document);
  if (vector.expect_error !== undefined) {
    assert(result.ok === false, envelope(result));
    assert(
      result.error === vector.expect_error,
      `expected ${vector.expect_error}, got ${result.error}`
    );
  } else {
    assert(result.ok === true, envelope(result));
    assert(
      result.value === vector.expected_canonical,
      `expected ${vector.expected_canonical}, got ${result.value}`
    );
  }
}

suite("canonical v1", canonicalV1.vectors, canonicalCheck);
suite("canonical v2", canonicalV2.vectors, canonicalCheck);
suite("canonical v3", canonicalV3.vectors, canonicalCheck);

function validationCheck(vector) {
  const { result } = kernel.decide({
    grant: vector.grant,
    signal: vector.signal,
    signer: vector.signer,
    now: vector.context.now,
    seen: vector.context.seen,
    counters: vector.context.counters,
    intent_spec: INTENT_SPEC,
    params_schema: PARAMS_SCHEMA,
  });
  assert(result.ok === true, envelope(result));
  assert(
    result.value === vector.expected,
    `expected ${vector.expected}, got ${result.value}`
  );
}

suite("validation v1", validationV1.vectors, validationCheck);
suite("validation v2", validationV2.vectors, validationCheck);
suite("validation v3", validationV3.vectors, validationCheck);

suite("state machine v1", stateMachine.vectors, (vector) => {
  const { result } = kernel.nextState({
    from: vector.from,
    event: vector.event,
  });
  assert(result.ok === true, envelope(result));
  assert(result.value === vector.to, `expected ${vector.to}, got ${result.value}`);
});

suite("ed25519 KAT", ed25519.kat_vectors, (vector) => {
  const { result } = kernel.sign({
    seed_hex: vector.secret_key_hex,
    message_hex: vector.message_hex,
  });
  assert(result.ok === true, envelope(result));
  assert(result.value.public_key_hex === vector.public_key_hex, "public key");
  assert(result.value.key_id === vector.key_id, "key id");
  assert(result.value.signature_hex === vector.signature_hex, "signature hex");
  assert(
    result.value.signature_field === vector.signature_field,
    "signature field"
  );

  const verified = kernel.verify({
    public_key_hex: vector.public_key_hex,
    message_hex: vector.message_hex,
    signature_field: vector.signature_field,
  });
  assert(verified.result.ok === true, envelope(verified.result));
  assert(verified.result.value === true, "verification failed");
});

suite("ed25519 signing", ed25519.signing_vectors, (vector) => {
  const { result } = kernel.signDocument({
    document: vector.document,
    seed_hex: vector.seed_hex,
  });
  assert(result.ok === true, envelope(result));
  assert(result.value.public_key_hex === vector.public_key_hex, "public key");
  assert(result.value.key_id === vector.key_id, "key id");
  assert(
    result.value.signature_field === vector.signature_field,
    "signature field"
  );
  assert(
    result.value.signing_input_sha256 === vector.signing_input_sha256,
    "signing hash"
  );
  assert(result.value.wire === vector.wire, "wire");
});

let failed = 0;
for (const entry of suites) {
  console.log(`${entry.name}: ${entry.passed}/${entry.total}`);
  failed += entry.total - entry.passed;
}
console.log(`wasm: ${failed === 0 ? "ok" : "FAILED"}`);
process.exitCode = failed === 0 ? 0 : 1;
