import type { JsonValue } from "./json.js";
import { serialize } from "./json.js";

type Schema = any;

/** Return human-readable violations; an empty array means valid. */
export function validate(value: JsonValue, schema: Schema): string[] {
  const errors: string[] = [];
  walk(value, schema, "$", errors);
  return errors;
}

export function isValid(value: JsonValue, schema: Schema): boolean {
  return validate(value, schema).length === 0;
}

function walk(
  value: JsonValue,
  schema: Schema,
  path: string,
  errors: string[]
): void {
  if (schema === false) {
    errors.push(`${path}: not allowed`);
    return;
  }
  if (schema === true || schema === null || schema === undefined) return;

  const expected = schema.type;
  if (expected !== undefined) {
    const names: string[] = Array.isArray(expected) ? expected : [expected];
    if (!names.some((name) => typeOk(value, name))) {
      errors.push(`${path}: expected ${names.join("/")}`);
      return;
    }
  }

  if ("const" in schema && !equal(value, schema.const)) {
    errors.push(`${path}: must equal const`);
  }
  if (
    "enum" in schema &&
    !schema.enum.some((candidate: JsonValue) => equal(value, candidate))
  ) {
    errors.push(`${path}: must be one of enum`);
  }

  if (typeof value === "bigint") numberChecks(value, schema, path, errors);
  else if (typeof value === "number" && Number.isSafeInteger(value)) {
    numberChecks(BigInt(value), schema, path, errors);
  }
  else if (typeof value === "string") stringChecks(value, schema, path, errors);
  else if (Array.isArray(value)) arrayChecks(value, schema, path, errors);
  else if (value !== null && typeof value === "object") {
    objectChecks(value, schema, path, errors);
  }
}

function typeOk(value: JsonValue, name: string): boolean {
  switch (name) {
    case "object":
      return value !== null && typeof value === "object" && !Array.isArray(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "integer":
      return (
        typeof value === "bigint" ||
        (typeof value === "number" && Number.isSafeInteger(value))
      );
    case "number":
      return (
        typeof value === "bigint" ||
        (typeof value === "number" && Number.isFinite(value))
      );
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    default:
      throw new Error(`unsupported type: ${name}`);
  }
}

function equal(a: JsonValue, b: JsonValue): boolean {
  if (typeof a === "bigint" || typeof b === "bigint") return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) {
      return false;
    }
    return a.every((item, index) => equal(item, b[index]));
  }
  if (
    a !== null &&
    b !== null &&
    typeof a === "object" &&
    typeof b === "object"
  ) {
    const keysA = Object.keys(a);
    const keysB = Object.keys(b);
    if (keysA.length !== keysB.length) return false;
    return keysA.every((key) => key in b && equal(a[key], b[key]));
  }
  return a === b;
}

function numberChecks(
  value: bigint,
  schema: Schema,
  path: string,
  errors: string[]
): void {
  if ("minimum" in schema && value < BigInt(schema.minimum)) {
    errors.push(`${path}: below minimum`);
  }
  if ("maximum" in schema && value > BigInt(schema.maximum)) {
    errors.push(`${path}: above maximum`);
  }
  if ("exclusiveMinimum" in schema && value <= BigInt(schema.exclusiveMinimum)) {
    errors.push(`${path}: not above exclusiveMinimum`);
  }
  if ("exclusiveMaximum" in schema && value >= BigInt(schema.exclusiveMaximum)) {
    errors.push(`${path}: not below exclusiveMaximum`);
  }
  if ("multipleOf" in schema) {
    const step = BigInt(schema.multipleOf);
    if (step !== 0n && value % step !== 0n) {
      errors.push(`${path}: not a multipleOf`);
    }
  }
}

function stringChecks(
  value: string,
  schema: Schema,
  path: string,
  errors: string[]
): void {
  // JSON Schema counts Unicode code points, not UTF-16 code units.
  const length = Array.from(value).length;
  if ("minLength" in schema && length < schema.minLength) {
    errors.push(`${path}: shorter than minLength`);
  }
  if ("maxLength" in schema && length > schema.maxLength) {
    errors.push(`${path}: longer than maxLength`);
  }
  if ("pattern" in schema && !new RegExp(schema.pattern).test(value)) {
    errors.push(`${path}: does not match pattern`);
  }
}

function arrayChecks(
  value: JsonValue[],
  schema: Schema,
  path: string,
  errors: string[]
): void {
  if ("minItems" in schema && value.length < schema.minItems) {
    errors.push(`${path}: fewer than minItems`);
  }
  if ("maxItems" in schema && value.length > schema.maxItems) {
    errors.push(`${path}: more than maxItems`);
  }
  if (schema.uniqueItems) {
    const keys = value.map((item) => serialize(item));
    if (new Set(keys).size !== keys.length) {
      errors.push(`${path}: items are not unique`);
    }
  }
  if (schema.items !== undefined) {
    value.forEach((item, index) =>
      walk(item, schema.items, `${path}[${index}]`, errors)
    );
  }
}

function objectChecks(
  value: { [key: string]: JsonValue },
  schema: Schema,
  path: string,
  errors: string[]
): void {
  const properties = schema.properties ?? {};
  for (const name of schema.required ?? []) {
    if (!(name in value)) errors.push(`${path}.${name}: required`);
  }
  const additional = schema.additionalProperties ?? true;
  for (const [name, item] of Object.entries(value)) {
    if (name in properties) {
      walk(item, properties[name], `${path}.${name}`, errors);
    } else if (additional === false) {
      errors.push(`${path}.${name}: additional property not allowed`);
    } else if (typeof additional === "object" && additional !== null) {
      walk(item, additional, `${path}.${name}`, errors);
    }
  }
}
