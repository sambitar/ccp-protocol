// @vitest-environment jsdom
import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { usePermissionCard } from "../src/adapters/react.js";
import { REQUESTER_PUBLIC, buildWorld, signalFor } from "./world.js";

const CARD = {
  title: "Look up an item",
  description: "Example Service wants to read item-123.",
};

describe("usePermissionCard", () => {
  it("asks for confirmation and authorizes after approve", async () => {
    const world = buildWorld({ confirmation: "per_action" });
    const signal = signalFor(world);
    const { result } = renderHook(() =>
      usePermissionCard({
        runtime: world.runtime,
        signal,
        publicKey: REQUESTER_PUBLIC,
        card: CARD,
      })
    );

    await waitFor(() =>
      expect(result.current.status).toBe("confirmation_required")
    );
    expect(result.current.card).toBe(CARD);

    await act(async () => result.current.approve());

    await waitFor(() => expect(result.current.status).toBe("authorized"));
    expect(result.current.decision?.outcome).toBe("authorized");
    expect(result.current.decision?.result).toEqual({
      item_id: "item-123",
      name: "Widget",
    });
  });

  it("cancels after deny", async () => {
    const world = buildWorld({ confirmation: "per_action" });
    const { result } = renderHook(() =>
      usePermissionCard({
        runtime: world.runtime,
        signal: signalFor(world),
        publicKey: REQUESTER_PUBLIC,
        card: CARD,
      })
    );

    await waitFor(() =>
      expect(result.current.status).toBe("confirmation_required")
    );
    await act(async () => result.current.deny());
    await waitFor(() => expect(result.current.status).toBe("cancelled"));
    expect(result.current.decision?.outcome).toBe("cancelled");
  });

  it("authorizes immediately when the grant needs no confirmation", async () => {
    const world = buildWorld();
    const { result } = renderHook(() =>
      usePermissionCard({
        runtime: world.runtime,
        signal: signalFor(world),
        publicKey: REQUESTER_PUBLIC,
        card: CARD,
      })
    );

    await waitFor(() => expect(result.current.status).toBe("authorized"));
  });

  it("reports a rejected signal", async () => {
    const world = buildWorld();
    const tampered = signalFor(world).replace('"item-123"', '"item-999"');
    const { result } = renderHook(() =>
      usePermissionCard({
        runtime: world.runtime,
        signal: tampered,
        publicKey: REQUESTER_PUBLIC,
        card: CARD,
      })
    );

    await waitFor(() => expect(result.current.status).toBe("rejected"));
    expect(result.current.decision?.error).toBe("unauthenticated");
  });

  it("ignores a stale confirmation after the signal changes", async () => {
    const world = buildWorld({ confirmation: "per_action" });
    const first = signalFor(world, { requestId: "req-1" });
    const second = signalFor(world, { requestId: "req-2" });
    const { result, rerender } = renderHook(
      ({ signal }: { signal: string }) =>
        usePermissionCard({
          runtime: world.runtime,
          signal,
          publicKey: REQUESTER_PUBLIC,
          card: CARD,
        }),
      { initialProps: { signal: first } }
    );

    await waitFor(() =>
      expect(result.current.status).toBe("confirmation_required")
    );
    const staleApprove = result.current.approve;

    rerender({ signal: second });
    await waitFor(() =>
      expect(result.current.status).toBe("confirmation_required")
    );

    await act(async () => staleApprove());
    expect(result.current.status).toBe("confirmation_required");
  });

  it("submits once per signal even when the key array is recreated", async () => {
    const world = buildWorld({ confirmation: "per_action" });
    const submit = vi.spyOn(world.runtime, "submit");
    const signal = signalFor(world);
    const { rerender } = renderHook(
      ({ key }: { key: Uint8Array }) =>
        usePermissionCard({
          runtime: world.runtime,
          signal,
          publicKey: key,
          card: CARD,
        }),
      { initialProps: { key: REQUESTER_PUBLIC } }
    );

    await waitFor(() => expect(submit).toHaveBeenCalledTimes(1));
    rerender({ key: new Uint8Array(REQUESTER_PUBLIC) });
    await Promise.resolve();
    expect(submit).toHaveBeenCalledTimes(1);
  });
});
