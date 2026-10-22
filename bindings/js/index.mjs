/**
 * Minimal loader for the CCP kernel WASM module.
 *
 * The module exposes a string-based C ABI. Every call returns a JSON
 * envelope: `{ok: true, value}` or `{ok: false, error}`.
 */
import { readFile } from "node:fs/promises";

export const DEFAULT_WASM = new URL(
  "../../kernel/target/wasm32-unknown-unknown/release/ccp_kernel.wasm",
  import.meta.url
);

export async function loadKernel(path = DEFAULT_WASM) {
  const bytes = await readFile(path);
  const { instance } = await WebAssembly.instantiate(bytes);
  return wrap(instance.exports);
}

export function wrap(exports) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function invoke(name, text) {
    const input = encoder.encode(text);
    const length = input.length;
    const pointer = length === 0 ? 0 : exports.ccp_alloc(length);
    if (length > 0) {
      new Uint8Array(exports.memory.buffer).set(input, pointer);
    }
    let code;
    try {
      code = exports[name](pointer, length);
    } finally {
      if (length > 0) exports.ccp_free(pointer, length);
    }

    // The call may have grown memory, so read the result view afterwards.
    const resultPointer = exports.ccp_result_ptr();
    const resultLength = exports.ccp_result_len();
    const output = new Uint8Array(
      exports.memory.buffer,
      resultPointer,
      resultLength
    );
    return { code, result: JSON.parse(decoder.decode(output)) };
  }

  return {
    canonicalize(document) {
      return invoke("ccp_canonicalize", document);
    },
    decide(input) {
      return invoke("ccp_decide", JSON.stringify(input));
    },
    nextState(input) {
      return invoke("ccp_next_state", JSON.stringify(input));
    },
    sign(input) {
      return invoke("ccp_sign", JSON.stringify(input));
    },
    verify(input) {
      return invoke("ccp_verify", JSON.stringify(input));
    },
    signDocument(input) {
      return invoke("ccp_sign_document", JSON.stringify(input));
    },
  };
}
