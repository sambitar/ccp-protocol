//! A complete Rust runtime for the Capability Contacts Protocol.
//!
//! The deterministic core lives in `ccp-kernel`. This crate adds the state a
//! runtime owns: grants, a replay set, limit counters, pending confirmations,
//! a host registry, identity documents, admission policies, and an audit log.
//!
//! ```
//! use ccp_runtime::Runtime;
//!
//! let runtime = Runtime::default();
//! assert!(runtime.supported_ccp.contains(&"0.5-draft".to_string()));
//! ```
//!
//! The runtime is synchronous and takes `&mut self` for mutations. Callers own
//! concurrency. No transport, async runtime, or FFI layer is included.

pub mod consumer;
pub mod errors;
pub mod grants;
pub mod hosts;
pub mod identity;
pub mod model;
pub mod runtime;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod stores;
pub mod time;
pub mod util;
pub mod vectors;

pub use consumer::{
    permission_card, required_capabilities, verify_manifest, verify_signal, PermissionCardOptions,
};
pub use errors::{CcpError, HostProfileError, IdentityError};
pub use grants::{create_grant, CreateGrantOptions, ManifestSource};
pub use hosts::{
    validate_host_profile, EgressPolicy, HostAccess, HostEntry, HostFunction, HostProfile,
    HostRegistry, IntentExecutor, NormalizedHostProfile, CORE_HOSTS,
};
pub use identity::{
    admit, admitted_grant, admitted_grant_id, build_admission_policy, build_identity_document,
    identity_digest, policy_digest, verify_admission_policy, verify_identity_document,
    AdmissionPolicyInput, IdentityInput, VerifyIdentityOptions, VerifyPolicyOptions,
    IDENTITY_CLOCK_SKEW_SECONDS, IDENTITY_TYPE, POLICY_TYPE,
};
pub use model::{
    AdmissionRequest, AdmissionResult, AdmitRequestResult, AdmittedGrant, Decision, Endpoint,
    Grant, PendingRequest, PermissionCard, PolicyRule, VerifiedIdentity, VerifiedManifest,
    VerifiedPolicy, VerifiedSignal, VerifyContactOptions,
};
pub use runtime::{
    key_id, public_key, Clock, Runtime, RuntimeOptions, SchemaRegistry, IDENTITY_CHANGED_REASON,
};
pub use stores::{
    AuditStore, GrantStore, LimitStore, ManifestStore, MemoryAuditLog, MemoryGrantStore,
    MemoryLimitStore, MemoryManifestStore, MemoryPendingStore, MemoryReplayStore, MemoryStores,
    PendingStore, ReplayStore,
};
