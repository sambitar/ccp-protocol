"""CCP reference runtime and SDK.

Assembles the protocol primitives into a runtime that verifies manifests
and signals, enforces local grants, mediates host functions, supports
two-phase confirmation, and keeps a private audit log.
"""

from .audit import AuditLog
from .agent import Agent, attenuates
from .canonical import CanonicalError, canonicalize, signed_wire, signing_bytes
from .consumer import (
    PermissionCard,
    permission_card,
    verify_manifest,
    verify_signal,
)
from .crypto import CryptoError, SigningKey, VerifyingKey
from .decision import decide
from .errors import AUTHORIZED, CONFIRMATION_REQUIRED, ERROR_CODES, CCPError
from .hosts import (
    CORE_HOSTS,
    HostAccess,
    HostProfileError,
    HostRegistry,
    validate_host_profile,
)
from .grants import create_grant
from .identity import (
    AdmissionRequest,
    AdmissionResult,
    AdmittedGrant,
    CLOCK_SKEW_SECONDS,
    IDENTITY_TYPE,
    POLICY_TYPE,
    IdentityError,
    PolicyRule,
    VerifiedIdentity,
    VerifiedPolicy,
    admit,
    admitted_grant,
    admitted_grant_id,
    build_admission_policy,
    build_identity_document,
    identity_digest,
    policy_digest,
    verify_admission_policy,
    verify_identity_document,
)
from .model import Decision, Grant, Manifest, Signal
from .requester import (
    Requester,
    build_manifest,
    build_signal,
    sign_manifest,
    sign_signal,
)
from .runtime import IDENTITY_CHANGED_REASON, AdmitRequestResult, Runtime
from .signing import sign_document
from .stores import (
    GrantStore,
    LimitTracker,
    ManifestStore,
    Pending,
    PendingStore,
    ReplayStore,
    SchemaRegistry,
)
from .stores_sqlite import (
    SqliteAuditLog,
    SqliteGrantStore,
    SqliteLimitTracker,
    SqliteManifestStore,
    SqlitePendingStore,
    SqliteReplayStore,
    SqliteStores,
)

__all__ = [
    "AdmissionRequest",
    "AdmissionResult",
    "AdmittedGrant",
    "AdmitRequestResult",
    "Agent",
    "AuditLog",
    "AUTHORIZED",
    "CONFIRMATION_REQUIRED",
    "CLOCK_SKEW_SECONDS",
    "CORE_HOSTS",
    "CanonicalError",
    "CCPError",
    "CryptoError",
    "Decision",
    "ERROR_CODES",
    "Grant",
    "GrantStore",
    "HostAccess",
    "HostProfileError",
    "HostRegistry",
    "IDENTITY_CHANGED_REASON",
    "IDENTITY_TYPE",
    "IdentityError",
    "LimitTracker",
    "Manifest",
    "ManifestStore",
    "Pending",
    "PendingStore",
    "PermissionCard",
    "POLICY_TYPE",
    "PolicyRule",
    "ReplayStore",
    "Requester",
    "Runtime",
    "SchemaRegistry",
    "SigningKey",
    "Signal",
    "SqliteAuditLog",
    "SqliteGrantStore",
    "SqliteLimitTracker",
    "SqliteManifestStore",
    "SqlitePendingStore",
    "SqliteReplayStore",
    "SqliteStores",
    "VerifyingKey",
    "VerifiedIdentity",
    "VerifiedPolicy",
    "admit",
    "admitted_grant",
    "admitted_grant_id",
    "attenuates",
    "build_admission_policy",
    "build_identity_document",
    "build_manifest",
    "build_signal",
    "canonicalize",
    "create_grant",
    "decide",
    "identity_digest",
    "permission_card",
    "policy_digest",
    "sign_document",
    "sign_manifest",
    "sign_signal",
    "signed_wire",
    "signing_bytes",
    "verify_manifest",
    "verify_admission_policy",
    "verify_identity_document",
    "verify_signal",
    "validate_host_profile",
]
