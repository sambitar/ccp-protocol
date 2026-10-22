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

## Extension hosts

These are review candidates, not a registry. A runtime that installs one is
responsible for its contract, and high-risk hosts require an independent
review before deployment. Every extension host must declare a class; the
runtime refuses to register it otherwise.

No payment host or intent is planned for 1.0. The payment rows are a design
sketch for a possible extension profile.

| Host | Class | Risk | Floor | Idempotency | Placement | Egress |
| --- | --- | --- | --- | --- | --- | --- |
| `payment.address.resolve` | read | read | none | pure | local | none |
| `calendar.read` | read | read | none | pure | local | none |
| `contacts.read` | read | read | none | pure | local | none |
| `mail.search` | read | read | none | pure | local | none |
| `store.write` | write | write | per_action | caller_key | local | none |
| `files.write` | write | write | per_action | atomic | local | none |
| `net.request` | disclose | disclose | per_action | caller_key | local, remote | declared fields |
| `device.operation` | control | irreversible | per_action | none | local | none |
| `model.infer` | compute | disclose | per_action | pure | local, remote | prompt, response |
| `payment.prepare` | write | write | per_action | caller_key | local, remote | payee, amount |
| `payment.submit` | write | irreversible | per_action | none | local, remote | payment_id |

`Floor` is the confirmation floor: the runtime requires per-action
confirmation even if the manifest claims `none`, and a policy that tries to
admit the intent unattended is refused with `risk_not_admittable`.

The machine-readable form of this table is `test-vectors/v5/hosts.json`;
all three runtimes validate it, so a profile cannot drift between languages.

### Intent vs host names

The table lists host identifiers. `payment.address.resolve` is a host name
here; §21.1 reuses the same string as an illustrative intent. That collision
is a sketch, not a naming precedent. A future extension profile should use
`wallet.*` host names, keep intents in their own namespace, and add a v6
vector suite rather than editing v5.

### Review questions (Appendix B)

Every extension must answer: who may request it; the exact effect; data read,
disclosed, modified, or deleted; required hosts; placement; what leaves the
device; enforceable limits; irreversible effects; confirmation policy;
duplicate/retry/crash behavior; what revocation can and cannot undo; what the
result may leak; and what metadata remains visible.

### Registering a host

A host declares its contract. Core hosts may omit it; an extension host
without a class is rejected at registration time.

```ts
hosts.registerHost("store.read", (id) => store[id]);
// -> class read, risk read, floor none, local, offline, no fields

hosts.registerHost("net.request", (url) => fetch(url), {
  class: "disclose",
  network: true,
  placement: ["local", "remote"],
  fields: ["url", "method", "body"],
});
```

```python
hosts.register_host("store.read", lambda item_id: store[item_id])
hosts.register_host(
    "net.request",
    lambda url: fetch(url),
    host_class="disclose",
    network=True,
    placement=["local", "remote"],
    fields=["url", "method", "body"],
)
```

A class fixes the defaults; the installer may tighten them but not loosen
what matters:

| Class | Risk | Floor | Idempotency |
| --- | --- | --- | --- |
| `read` | read | none | pure |
| `disclose` | disclose | per_action | pure |
| `write` | write | per_action | caller_key |
| `control` | write | per_action | none |
| `compute` | read | per_action | pure |

A `write`, `control`, or `compute` host cannot set the floor to `none`, and
an `irreversible` risk cannot either. A network `disclose` host must declare
the fields it sends.

The runtime compares the contract against the intent and the grant before
every invocation:

| Check | Refusal |
| --- | --- |
| Intent placement is in `grant.placement` | `capability_unavailable` |
| Host supports the intent's placement | `capability_unavailable` |
| Host needs network only if `grant.egress.network` is true | `capability_unavailable` |
| Every host field is in `grant.egress.fields` | `capability_unavailable` |
| A per-action floor forces confirmation | `confirmation_required` |
| A per-action floor blocks policy admission | `risk_not_admittable` |

The same egress ceiling is re-checked on each `HostAccess.call`, so an
executor cannot reach past the grant with a dynamic call.

## Hard rules

- A provider description or registry badge never authorizes anything
  (§19.3).
- No host ships executable provider code in the initial profile.
- A failed or unknown capability check fails closed.
- `payment.submit` and `device.operation` are not suitable for unattended
  agents without an independent review and a trusted confirmation path.
