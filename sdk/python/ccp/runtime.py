"""Reference CCP runtime: validation, confirmation, execution, audit.

Implements the §10.3 validation sequence and the §26.3 side-effect state
machine. Confirmation is two-phase: :meth:`Runtime.submit` returns
``confirmation_required`` with a ``pending_id``, and the trusted client
later calls :meth:`Runtime.confirm`.
"""

import uuid
from dataclasses import dataclass

from . import canonical, crypto, schema
from .audit import AuditLog, utcnow
from .consumer import verify_manifest
from .decision import DEFAULT_SUPPORTED_CCP, decide
from .errors import AUTHORIZED, CONFIRMATION_REQUIRED, CCPError
from .grants import create_grant
from .hosts import HostRegistry
from .identity import (
    AdmissionResult,
    IdentityError,
    admit,
    admitted_grant,
    verify_identity_document,
)
from .model import Decision, Signal

IDENTITY_CHANGED_REASON = "identity_changed"


@dataclass
class AdmitRequestResult:
    """Outcome of a policy admission (§25.8.3)."""

    result: AdmissionResult
    grant: object = None
from .stores import (
    GrantStore,
    LimitTracker,
    ManifestStore,
    Pending,
    PendingStore,
    ReplayStore,
    SchemaRegistry,
)


class Runtime:
    def __init__(self, *, grants=None, manifests=None, replay=None, limits=None,
                 pending=None, schemas=None, hosts=None, audit=None, clock=None,
                 supported_ccp=DEFAULT_SUPPORTED_CCP):
        self.grants = grants if grants is not None else GrantStore()
        self.manifests = manifests if manifests is not None else ManifestStore()
        self.schemas = schemas if schemas is not None else SchemaRegistry()
        self.hosts = hosts if hosts is not None else HostRegistry()
        self.audit = audit if audit is not None else AuditLog()
        self.replay = replay if replay is not None else ReplayStore()
        self.limits = limits if limits is not None else LimitTracker()
        self.pending_store = pending if pending is not None else PendingStore()
        self.clock = clock or utcnow
        self.supported_ccp = supported_ccp

    # -- public API ------------------------------------------------------

    def submit(self, document, verifying_key=None):
        """Validate and act on one signed signal."""
        now = self.clock()
        try:
            signal = Signal.parse(document)
        except (canonical.CanonicalError, CCPError) as exc:
            return self._reject("invalid_request", None, detail=str(exc))
        request_id = signal.request_id

        # authenticate the sender (transport provides the bound key)
        if verifying_key is None:
            return self._reject("unauthenticated", request_id,
                                detail="no authenticated signer")
        try:
            if not verifying_key.verify(signal._signing_input,
                                        signal.data["signature"]):
                return self._reject("unauthenticated", request_id,
                                    detail="signature mismatch")
        except (crypto.CryptoError, KeyError) as exc:
            return self._reject("unauthenticated", request_id, detail=str(exc))

        signer = verifying_key.key_id

        # resolve the grant and its approved manifest
        grant = self._resolve_grant(signer, signal.data["grant_digest"],
                                    signal.data["intent"])
        intent_spec = None
        params_schema = None
        if grant is not None:
            manifest = self.manifests.get(grant.manifest_digest)
            if manifest is not None:
                intent_spec = manifest.intent_spec(signal.data["intent"])
                if intent_spec is not None:
                    params_schema = self.schemas.get(
                        intent_spec.get("params_schema"))
        counters = self.limits.counters(grant.id) if grant is not None else {}

        decision = decide(
            grant, signal.data, signer, now,
            self.replay.snapshot(), counters,
            intent_spec=intent_spec, params_schema=params_schema,
            supported_ccp=self.supported_ccp,
        )
        if decision not in (AUTHORIZED, CONFIRMATION_REQUIRED):
            return self._reject(decision, request_id, grant,
                                detail=self._state_detail(decision, grant))

        # accepted: apply replay and limit guards atomically
        if not self.replay.mark_if_new(request_id):
            return self._reject("replay_detected", request_id, grant)
        if not self.limits.try_reserve(grant.id, grant.limits):
            return self._reject("limit_exceeded", request_id, grant)

        required = intent_spec.get("required_capabilities", [])
        unavailable = [c for c in required if not self.hosts.has_host(c)]
        if unavailable or not self.hosts.has_intent(signal.data["intent"]):
            self.limits.release(grant.id, grant.limits)
            return self._reject("capability_unavailable", request_id, grant,
                                detail="unavailable: %s"
                                % (unavailable or signal.data["intent"]))

        deployment = self._deployment_error(grant, intent_spec, required)
        if deployment is not None:
            self.limits.release(grant.id, grant.limits)
            return self._reject("capability_unavailable", request_id, grant,
                                detail=deployment)

        if decision == CONFIRMATION_REQUIRED:
            pending_id = uuid.uuid4().hex
            self.pending_store.put(
                Pending(pending_id, signal, grant, intent_spec))
            self._audit("awaiting_confirmation", signal, grant)
            return Decision(CONFIRMATION_REQUIRED, request_id=request_id,
                            pending_id=pending_id,
                            state="awaiting_confirmation")

        return self._execute(signal, grant, intent_spec)

    def confirm(self, pending_id, approved):
        """Resolve a pending confirmation."""
        pending = self.pending_store.take(pending_id)
        if pending is None:
            return self._reject("invalid_request", None,
                                detail="unknown pending request")

        if not approved:
            self.limits.release(pending.grant.id, pending.grant.limits)
            self._audit("cancelled", pending.signal, pending.grant)
            return Decision("cancelled", request_id=pending.signal.request_id,
                            state="cancelled")

        # The grant may have changed while the prompt was open (§9.4.3);
        # re-read it rather than trusting the snapshot.
        current = self.grants.get(pending.grant.id) or pending.grant
        state_error = self._grant_state_error(current, self.clock())
        if state_error:
            self.limits.release(current.id, current.limits)
            return self._reject(state_error, pending.signal.request_id, current,
                                detail=self._state_detail(state_error, current))

        return self._execute(pending.signal, current, pending.intent_spec)

    def pending(self, pending_id):
        return self.pending_store.get(pending_id)

    # -- lifecycle (§9.4) ------------------------------------------------

    def pause_grant(self, grant_id, reason=None):
        """Pause one grant; configuration, limits, and history are kept."""
        return self._transition(grant_id, "paused", reason)

    def suspend_grant(self, grant_id, reason=None):
        """Suspend one grant pending a security or identity check."""
        return self._transition(grant_id, "suspended", reason)

    def revoke_grant(self, grant_id, reason=None):
        """Revoke one grant permanently (§9.4.4).

        Policy-created grants reuse their deterministic id, so revoking here
        also stops an admission rule from re-creating the same access
        (§25.8.3).
        """
        return self._transition(grant_id, "revoked", reason)

    def resume_grant(self, grant_id):
        """Resume a paused or suspended grant (§9.4.3).

        Re-checks revocation, expiry, and the approved manifest. A revoked or
        expired grant cannot be resumed.
        """
        grant = self.grants.get(grant_id)
        if grant is None:
            raise CCPError("no_matching_grant",
                           "unknown grant: %s" % (grant_id,))
        if grant.state == "revoked":
            raise CCPError("grant_revoked",
                           "a revoked grant cannot be resumed")
        if (grant.state == "suspended"
                and grant.state_reason == IDENTITY_CHANGED_REASON):
            raise CCPError(
                "grant_suspended",
                "identity changed; re-introduce the contact and create a "
                "new grant")
        if grant.state == "expired" or self.clock() >= grant.expires_at:
            raise CCPError("grant_expired",
                           "an expired grant cannot be resumed")
        if self.manifests.get(grant.manifest_digest) is None:
            raise CCPError("capability_unavailable",
                           "the approved manifest is no longer stored")
        if grant.state == "active":
            return grant
        return self._set_state(grant, "active")

    def suspend_contact(self, contact_id, reason=None):
        """Suspend every non-revoked grant bound to a contact (§7.4)."""
        affected = [grant for grant in self.grants.all()
                    if grant.contact_id == contact_id
                    and grant.state != "revoked"]
        for grant in affected:
            self._set_state(grant, "suspended",
                            reason or "contact suspended")
        return len(affected)

    def verify_contact_identity(self, document, contact_id, **options):
        """Verify an identity document for a known contact (§7.4).

        On ``identity_changed`` — a valid signature from a different key —
        the contact's grants are suspended before the error is re-raised. A
        bad signature never suspends anything, so an attacker cannot force a
        suspension by sending garbage.
        """
        try:
            return verify_identity_document(document, **options)
        except IdentityError as exc:
            if exc.code == "identity_changed":
                suspended = self.suspend_contact(
                    contact_id, IDENTITY_CHANGED_REASON)
                self.audit.append({
                    "event": "identity_changed",
                    "contact_id": contact_id,
                    "detail": "%d grant(s) suspended" % suspended,
                })
            raise

    def _transition(self, grant_id, state, reason=None):
        grant = self.grants.get(grant_id)
        if grant is None:
            raise CCPError("no_matching_grant",
                           "unknown grant: %s" % (grant_id,))
        if grant.state == "revoked" and state != "revoked":
            raise CCPError("grant_revoked", "a revoked grant is final")
        return self._set_state(grant, state, reason)

    def _set_state(self, grant, state, reason=None):
        grant.state = state
        grant.state_reason = (None if state == "active"
                             else reason or grant.state_reason)
        self.grants.add(grant)
        self._audit("resumed" if state == "active" else state,
                    None, grant, detail=reason)
        return grant

    @staticmethod
    def _state_detail(decision, grant):
        if grant is None:
            return None
        if decision in ("grant_revoked", "grant_paused", "grant_suspended"):
            return grant.state_reason
        return None

    def _resolve_grant(self, requester_key, manifest_digest, intent):
        """Prefer a grant that enables the intent when several share a digest."""
        found = self.grants.find(requester_key, manifest_digest)
        if found is not None and intent in found.intents:
            return found
        candidates = [grant for grant in self.grants.all()
                      if grant.requester_key == requester_key
                      and grant.manifest_digest == manifest_digest
                      and intent in grant.intents]
        if not candidates:
            return found
        for grant in candidates:
            if grant.state == "active":
                return grant
        return candidates[0]

    # -- admission (§25.8.3) ---------------------------------------------

    def admit_request(self, policy, request, manifest, confirmation=None):
        """Admit a request under a reviewed policy.

        ``allow`` creates or reuses the grant with the policy's deterministic
        id, records the admitting rule, and leaves the request to proceed
        through :meth:`submit`. Revoked ids are read from the grant store, so
        a revocation is never undone here.
        """
        verified = (verify_manifest(manifest)
                    if isinstance(manifest, str) else manifest)
        revoked = {grant.id for grant in self.grants.all()
                   if grant.state == "revoked"}
        result = admit(policy, request, revoked=revoked)
        if result.decision != "allow":
            return AdmitRequestResult(result)

        granted = admitted_grant(policy, request, result)
        existing = self.grants.get(granted.id)
        if existing is not None:
            return AdmitRequestResult(result, existing)

        grant = create_grant(
            grant_id=granted.id,
            contact_id=request.contact_id,
            requester_key=request.requester_key,
            manifest=verified,
            intents=[granted.intent],
            limits=granted.limits,
            confirmation=confirmation or {granted.intent: "none"},
            created_at=self.clock(),
            expires_at=granted.expires_at,
            admitted_by=result.rule_id,
        )
        self.grants.add(grant)
        self.manifests.add(verified)
        self.audit.append({"event": "admitted", "grant_id": grant.id,
                           "intent": granted.intent,
                           "rule_id": result.rule_id})
        return AdmitRequestResult(result, grant)

    # -- internals -------------------------------------------------------

    def _execute(self, signal, grant, intent_spec):
        self._audit("executing", signal, grant)
        executor = self.hosts.intent(signal.data["intent"])
        access = self.hosts.access(grant.capabilities,
                                   self._egress_policy(grant))
        try:
            result = executor(signal.data["params"], access)
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed outcome
            self.limits.release(grant.id, grant.limits)
            self._audit("failed", signal, grant, detail=str(exc))
            return Decision("execution_failed", request_id=signal.request_id,
                            error="execution_failed", detail=str(exc),
                            state="failed")

        result_schema = self.schemas.get(intent_spec.get("result_schema"))
        if result_schema is not None:
            problems = schema.validate(result, result_schema)
            if problems:
                self.limits.release(grant.id, grant.limits)
                self._audit("failed", signal, grant, detail="invalid result")
                return Decision("execution_failed", request_id=signal.request_id,
                                error="execution_failed",
                                detail="invalid result: " + "; ".join(problems),
                                state="failed")

        self.limits.commit(grant.id, grant.limits)
        self._audit("completed", signal, grant)
        return Decision(AUTHORIZED, request_id=signal.request_id,
                        result=result, state="completed")

    @staticmethod
    def _egress_policy(grant):
        egress = grant.egress or {}
        fields = egress.get("fields")
        return {
            "network": egress.get("network") is True,
            "fields": frozenset(fields) if isinstance(fields, list) else frozenset(),
        }

    def _deployment_error(self, grant, intent_spec, required):
        """Enforce the grant's placement and egress ceilings (§12)."""
        placement = intent_spec.get("placement") or "local"
        if placement not in (grant.placement or []):
            return "placement %s is not granted" % (placement,)

        policy = self._egress_policy(grant)
        for capability in required:
            meta = self.hosts.host_meta(capability)
            if meta is None:
                return "host %s is not installed" % (capability,)
            if placement not in meta["placement"]:
                return ("host %s cannot run with %s placement"
                        % (capability, placement))
            if meta["network"] and not policy["network"]:
                return ("host %s requires network egress not granted"
                        % (capability,))
            for field in meta["fields"]:
                if field not in policy["fields"]:
                    return ("host %s may send undeclared field %s"
                            % (capability, field))
        return None

    @staticmethod
    def _grant_state_error(grant, now):
        if grant.state == "revoked":
            return "grant_revoked"
        if grant.state == "paused":
            return "grant_paused"
        if grant.state == "suspended":
            return "grant_suspended"
        if grant.state == "expired" or now >= grant.expires_at:
            return "grant_expired"
        return None

    def _reject(self, code, request_id, grant=None, detail=None):
        self._audit("rejected", None, grant, request_id=request_id,
                    code=code, detail=detail)
        return Decision(code, request_id=request_id, error=code, detail=detail)

    def _audit(self, event, signal=None, grant=None, request_id=None,
               code=None, detail=None):
        record = {"event": event, "grant_id": grant.id if grant else None}
        if signal is not None:
            record["request_id"] = signal.request_id
            record["intent"] = signal.data.get("intent")
        if request_id is not None:
            record["request_id"] = request_id
        if code is not None:
            record["code"] = code
        if detail is not None:
            record["detail"] = detail
        self.audit.append(record)
