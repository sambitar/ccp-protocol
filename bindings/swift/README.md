# CCP — Swift binding (not implemented)

This directory is a placeholder. There are no Swift sources and no
`Package.swift`; nothing here builds or ships.

When implemented, the binding will wrap the kernel's C ABI, so it will expose
only the deterministic core: canonical JSON, Ed25519, the schema subset, the
§10.3 decision, and the §26.3 state machine. It will not include a grant
store, replay store, limit counters, host registry, audit log, or transport.

For an end-to-end runtime today, use `sdk/typescript` or `sdk/python`. See
[`docs/implementation-status.md`](../../docs/implementation-status.md).
