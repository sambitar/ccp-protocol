# Host capability catalogue

The runtime executes intents only through installed host functions (§26.4).
An intent whose required capability is not installed is rejected with
`capability_unavailable`; there is no fallback.

Only the six **core** hosts below are part of the initial profile. Everything
under *extension candidates* is a proposal: none is enabled by the SDKs, and
each needs its own review (§19.2, §25.6) before a runtime may expose it.

Host identifiers (`store.read`, `files.search`, …) are a runtime namespace,
not a publisher namespace. Intent naming is covered in
[`namespaces.md`](namespaces.md).

## Core hosts (§26.4)

| Host | Purpose | Class | Contract notes |
| --- | --- | --- | --- |
| `store.read` | read a specifically granted store or item | read | Input identifies the item; output is the stored value. No writes. |
| `files.read` | read scoped files or directories | read | Path scope must come from the grant, not the request. |
| `files.search` | search a scoped folder | read | Returned paths are scoped; no content exfiltration beyond declared fields. |
| `notify` | show a local notification | control | No external side effect; content is untrusted display data. |
| `confirm` | request a decision through trusted UI | control | Must show the runtime-generated §11.4 card; never auto-approves. |
| `audit.append` | write a runtime-controlled audit event | control | Append-only; the intent cannot alter past records. |

## Extension candidates

These are review candidates, not a registry. A runtime that installs one is
responsible for its contract, and high-risk hosts require an independent
review before deployment.

| Host | Class | Minimum scope | Confirmation | Idempotency / recovery | Egress |
| --- | --- | --- | --- | --- | --- |
| `payment.address.resolve` | read | saved addresses only | none | pure read | none |
| `calendar.read` | read | one calendar + time window | policy | pure read | none |
| `contacts.read` | read | selected contact fields | policy | pure read | none |
| `mail.search` | read | one mailbox + query | policy | pure read | none |
| `store.write` | write | named keys + size cap | per action | caller-supplied idempotency key; read-back reconciliation | none |
| `files.write` | write | one directory + extension allow-list | per action | temp file + atomic rename; overwrite requires explicit scope | none |
| `net.request` | egress | host allow-list + methods | per action | idempotency key for non-GET; response is untrusted data | declared fields only |
| `device.operation` | control | named operation | per action, trusted UI | operation-specific; default no retry | none |
| `model.infer` | compute | provider + model + token cap | policy | deterministic where possible; no silent retries | prompt/response fields |
| `payment.prepare` | write | amount cap + payee allow-list | per action | creates a pending intent, no transfer | payee metadata only |
| `payment.submit` | high | prepared intent + second confirmation | per action | never auto-retry; reconcile by payment id | payment metadata |

### Review questions (Appendix B)

Every extension must answer: who may request it; the exact effect; data read,
disclosed, modified, or deleted; required hosts; placement; what leaves the
device; enforceable limits; irreversible effects; confirmation policy;
duplicate/retry/crash behavior; what revocation can and cannot undo; what the
result may leak; and what metadata remains visible.

### Hard rules

- A provider description or registry badge never authorizes anything
  (§19.3).
- No host ships executable provider code in the initial profile.
- A failed or unknown capability check fails closed.
- `payment.submit` and `device.operation` are not suitable for unattended
  agents without an independent review and a trusted confirmation path.
