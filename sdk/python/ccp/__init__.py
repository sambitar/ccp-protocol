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
from .hosts import HostAccess, HostRegistry
from .model import Decision, Grant, Manifest, Signal
from .requester import (
    Requester,
    build_manifest,
    build_signal,
    sign_manifest,
    sign_signal,
)
from .runtime import Runtime
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
    "Agent",
    "AuditLog",
    "AUTHORIZED",
    "CONFIRMATION_REQUIRED",
    "CanonicalError",
    "CCPError",
    "CryptoError",
    "Decision",
    "ERROR_CODES",
    "Grant",
    "GrantStore",
    "HostAccess",
    "HostRegistry",
    "LimitTracker",
    "Manifest",
    "ManifestStore",
    "Pending",
    "PendingStore",
    "PermissionCard",
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
    "attenuates",
    "build_manifest",
    "build_signal",
    "canonicalize",
    "decide",
    "permission_card",
    "sign_document",
    "sign_manifest",
    "sign_signal",
    "signed_wire",
    "signing_bytes",
    "verify_manifest",
    "verify_signal",
]
