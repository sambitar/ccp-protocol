import { describe, expect, it } from "vitest";
import { buildIdentityDocument, IdentityError } from "../src/identity.js";
import { IDENTITY_CHANGED_REASON } from "../src/runtime.js";
import {
  NOW,
  REQUESTER_PUBLIC,
  REQUESTER_SEED,
  buildWorld,
  signalFor,
} from "./world.js";

const OTHER_SEED = Uint8Array.from({ length: 32 }, (_, index) => index + 96);
const ISSUED = "2026-10-22T00:00:00Z";
const UNTIL = "2027-10-22T00:00:00Z";

function document(seed: Uint8Array): string {
  return buildIdentityDocument(
    { name: "Peer", issuedAt: ISSUED, expiresAt: UNTIL },
    seed
  );
}

function auditEvents(world: ReturnType<typeof buildWorld>): any[] {
  return (world.runtime.audit as unknown as { events(): any[] }).events();
}

describe("Runtime.verifyContactIdentity", () => {
  it("verifies a matching document without touching grants", async () => {
    const world = buildWorld();
    const verified = await world.runtime.verifyContactIdentity(
      document(REQUESTER_SEED),
      {
        contactId: "c-1",
        expectedIdentity: world.requesterId,
        now: NOW,
      }
    );
    expect(verified.identity).toBe(world.requesterId);
    expect((await world.runtime.grants.get("g-1"))?.state).toBe("active");
  });

  it("suspends the contact's grants when the key changed", async () => {
    const world = buildWorld();

    await expect(
      world.runtime.verifyContactIdentity(document(OTHER_SEED), {
        contactId: "c-1",
        expectedIdentity: world.requesterId,
        now: NOW,
      })
    ).rejects.toBeInstanceOf(IdentityError);

    const grant = await world.runtime.grants.get("g-1");
    expect(grant?.state).toBe("suspended");
    expect(grant?.state_reason).toBe(IDENTITY_CHANGED_REASON);

    expect(
      auditEvents(world).some((event) => event.event === "identity_changed")
    ).toBe(true);

    const decision = await world.runtime.submit(
      signalFor(world),
      REQUESTER_PUBLIC
    );
    expect(decision.error).toBe("grant_suspended");
  });

  it("does not let a key change be resumed in one click", async () => {
    const world = buildWorld();
    await expect(
      world.runtime.verifyContactIdentity(document(OTHER_SEED), {
        contactId: "c-1",
        expectedIdentity: world.requesterId,
        now: NOW,
      })
    ).rejects.toBeInstanceOf(IdentityError);

    await expect(world.runtime.resumeGrant("g-1")).rejects.toMatchObject({
      code: "grant_suspended",
    });
  });

  it("never suspends on a forged document", async () => {
    const world = buildWorld();
    const forged = document(REQUESTER_SEED).replace("Peer", "Evil");

    await expect(
      world.runtime.verifyContactIdentity(forged, {
        contactId: "c-1",
        expectedIdentity: world.requesterId,
        now: NOW,
      })
    ).rejects.toMatchObject({ code: "unauthenticated" });

    expect((await world.runtime.grants.get("g-1"))?.state).toBe("active");
  });

  it("still allows a manual suspend to resume", async () => {
    const world = buildWorld();
    await world.runtime.suspendGrant("g-1", "manual review");
    expect((await world.runtime.resumeGrant("g-1")).state).toBe("active");
  });
});
