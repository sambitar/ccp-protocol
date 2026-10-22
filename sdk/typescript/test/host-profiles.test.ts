import { describe, expect, it } from "vitest";
import {
  CORE_HOSTS,
  HostProfileError,
  HostRegistry,
  validateHostProfile,
} from "../src/runtime.js";

describe("host profiles", () => {
  it("requires a class for every extension host", () => {
    const registry = new HostRegistry();
    expect(() => registry.registerHost("net.request", () => 1)).toThrow(
      HostProfileError
    );
    expect(() => registry.registerHost("net.request", () => 1)).toThrow(
      /requires a class/
    );
  });

  it("accepts core hosts without a profile", () => {
    const registry = new HostRegistry();
    registry.registerHost("store.read", () => 1);
    expect(registry.hostMeta("store.read")?.profile).toEqual({
      class: "read",
      risk: "read",
      minConfirmation: "none",
      idempotency: "pure",
      network: false,
      placement: ["local"],
      fields: [],
    });
  });

  it("derives a per-action floor for write, control, and compute", () => {
    expect(validateHostProfile("store.write", { class: "write" })).toMatchObject({
      risk: "write",
      minConfirmation: "per_action",
      idempotency: "caller_key",
    });
    expect(
      validateHostProfile("device.operation", {
        class: "control",
        risk: "irreversible",
      })
    ).toMatchObject({ risk: "irreversible", minConfirmation: "per_action" });
    expect(
      validateHostProfile("model.infer", { class: "compute" }).minConfirmation
    ).toBe("per_action");
  });

  it("never lets a write host suppress confirmation", () => {
    expect(() =>
      validateHostProfile("store.write", {
        class: "write",
        minConfirmation: "none",
      })
    ).toThrow(/cannot suppress confirmation/);
  });

  it("never lets an irreversible host suppress confirmation", () => {
    expect(() =>
      validateHostProfile("payment.submit", {
        class: "write",
        risk: "irreversible",
        minConfirmation: "none",
      })
    ).toThrow(/cannot suppress confirmation/);
  });

  it("requires declared fields for a network disclose host", () => {
    expect(() =>
      validateHostProfile("net.request", { class: "disclose", network: true })
    ).toThrow(/fields/);
  });

  it("rejects unknown placements and duplicate fields", () => {
    expect(() =>
      validateHostProfile("net.request", {
        class: "disclose",
        network: true,
        placement: ["edge"] as any,
        fields: ["q"],
      })
    ).toThrow(/placement/);
    expect(() =>
      validateHostProfile("net.request", {
        class: "disclose",
        network: true,
        fields: ["q", "q"],
      })
    ).toThrow(/duplicate/);
  });

  it("pins the core catalogue", () => {
    expect([...CORE_HOSTS]).toEqual([
      "store.read",
      "files.read",
      "files.search",
      "notify",
      "confirm",
      "audit.append",
    ]);
  });
});
