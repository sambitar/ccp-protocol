import { randomBytes } from "@noble/hashes/utils";

/** 16 random bytes as lowercase hex. */
export function randomId(): string {
  return Array.from(randomBytes(16))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
