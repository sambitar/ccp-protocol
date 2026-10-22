"""Reference CCP runtime: validation, confirmation, execution, audit.

Implements the §10.3 validation sequence and the §26.3 side-effect state
machine. Confirmation is two-phase: :meth:`Runtime.submit` returns
``confirmation_required`` with a ``pending_id``, and the trusted client
later calls :meth:`Runtime.confirm`.
"""

import uuid

from . import canonical, crypto, schema
from .audit import AuditLog, utcnow
from .decision import DEFAULT_SUPPORTED_CCP, decide
from .errors import AUTHORIZED, CONFIRMATION_REQUIRED, CCPError
from .hosts import HostRegistry
from .model import Decision, Signal
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
        grant = self.grants.find(signer, signal.data["grant_digest"])
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
            return self._reject(decision, request_id, grant)

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

        # The grant may have changed while the prompt was open (§9.4.3).
        state_error = self._grant_state_error(pending.grant, self.clock())
        if state_error:
            self.limits.release(pending.grant.id, pending.grant.limits)
            return self._reject(state_error, pending.signal.request_id,
                                pending.grant)

        return self._execute(pending.signal, pending.grant, pending.intent_spec)

    def pending(self, pending_id):
        return self.pending_store.get(pending_id)

    # -- internals -------------------------------------------------------

    def _execute(self, signal, grant, intent_spec):
        self._audit("executing", signal, grant)
        executor = self.hosts.intent(signal.data["intent"])
        access = self.hosts.access(grant.capabilities)
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
