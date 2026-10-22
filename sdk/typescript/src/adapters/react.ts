import { useCallback, useEffect, useRef, useState } from "react";

import type { Decision, Runtime } from "../runtime.js";
import { AUTHORIZED, CONFIRMATION_REQUIRED } from "../errors.js";

export type PermissionStatus =
  | "loading"
  | "authorized"
  | "confirmation_required"
  | "rejected"
  | "cancelled";

export interface PermissionCardOptions<T = unknown> {
  /** Runtime that owns grants, replay protection, limits, and executors. */
  runtime: Runtime;
  /** Canonical signed signal to submit. */
  signal: string;
  /** Requester public key that the runtime will verify the signal against. */
  publicKey: Uint8Array;
  /** Anything the caller wants to render; handed back untouched. */
  card?: T;
}

export interface PermissionCardResult<T = unknown> {
  status: PermissionStatus;
  card: T | undefined;
  decision: Decision | undefined;
  approve: () => void;
  deny: () => void;
}

interface Snapshot {
  signal: string;
  status: PermissionStatus;
  decision?: Decision;
}

/**
 * Headless permission card for the consuming side: submit a signed signal,
 * surface whether it needs confirmation, and let the user approve or deny.
 * Presentation is entirely the caller's.
 */
export function usePermissionCard<T = unknown>(
  options: PermissionCardOptions<T>
): PermissionCardResult<T> {
  const { runtime, signal, publicKey, card } = options;
  const [snapshot, setSnapshot] = useState<Snapshot>({
    signal,
    status: "loading",
  });
  const submittedSignal = useRef<string | undefined>(undefined);
  const pending = useRef<{ signal: string; id: string } | undefined>(undefined);

  useEffect(() => {
    if (submittedSignal.current === signal) return;
    submittedSignal.current = signal;
    pending.current = undefined;

    let cancelled = false;
    void runtime
      .submit(signal, publicKey)
      .then((decision) => {
        if (cancelled) return;
        if (decision.outcome === CONFIRMATION_REQUIRED && decision.pending_id) {
          pending.current = { signal, id: decision.pending_id };
        }
        setSnapshot({ signal, status: statusOf(decision), decision });
      })
      .catch(() => {
        if (!cancelled) setSnapshot({ signal, status: "rejected" });
      });

    return () => {
      cancelled = true;
    };
  }, [runtime, signal, publicKey]);

  const settle = useCallback(
    (approved: boolean) => {
      // A pending request only belongs to the signal that created it.
      if (pending.current?.signal !== signal) return;
      const id = pending.current.id;
      pending.current = undefined;

      void runtime
        .confirm(id, approved)
        .then((decision) => {
          setSnapshot({ signal, status: statusOf(decision), decision });
        })
        .catch(() => {
          setSnapshot({ signal, status: "rejected" });
        });
    },
    [runtime, signal]
  );

  const approve = useCallback(() => settle(true), [settle]);
  const deny = useCallback(() => settle(false), [settle]);

  const current =
    snapshot.signal === signal
      ? snapshot
      : { signal, status: "loading" as const, decision: undefined };

  return { status: current.status, card, decision: current.decision, approve, deny };
}

function statusOf(decision: Decision): PermissionStatus {
  if (decision.outcome === AUTHORIZED) return "authorized";
  if (decision.outcome === CONFIRMATION_REQUIRED) return "confirmation_required";
  if (decision.outcome === "cancelled") return "cancelled";
  return "rejected";
}
