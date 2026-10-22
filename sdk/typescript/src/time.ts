/** RFC 3339 UTC with second precision, as used by the canonical profile. */
export function utcnow(): string {
  return new Date().toISOString().replace(/\.\d+Z$/, "Z");
}
