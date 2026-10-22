import { describe, expect, it } from "vitest";
import { CcpError, ERROR_CODES } from "../src/errors.js";

describe("CcpError", () => {
  it("carries a known §10.4 code", () => {
    const error = new CcpError("limit_exceeded");
    expect(error.code).toBe("limit_exceeded");
    expect(error.message).toBe("limit_exceeded");
  });

  it("rejects unknown codes", () => {
    expect(() => new CcpError("nope")).toThrow(/unknown CCP error code/);
  });

  it("knows the rejection codes but not success outcomes", () => {
    expect(ERROR_CODES.has("replay_detected")).toBe(true);
    expect(ERROR_CODES.has("authorized")).toBe(false);
  });
});
