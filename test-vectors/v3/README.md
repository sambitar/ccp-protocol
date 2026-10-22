# CCP v3 conformance vectors

`../*.json` is the frozen v1 contract and `../v2/` is the adversarial v2
set. This directory is additive: it pins the 0.5 revision's dual-label
compatibility.

| File | Covers |
| --- | --- |
| `canonical-json.json` | canonical JSON is version-independent; a sort case and two rejections |
| `validation.json` | `0.5-draft` accepted, `0.4-draft` accepted as legacy, an unknown label rejected, replay, and grant expiry |

Formats match v1/v2: canonical cases carry `expected_canonical` or
`expect_error`; validation cases carry `grant`, `signal`, `signer`,
`context`, and `expected`.

## Why these cases

- `v3-001` pins the current label `0.5-draft`.
- `v3-002` keeps `0.4-draft` documents working (§19.1).
- `v3-003` rejects labels outside the accepted set.
- `v3-004`/`v3-005` re-check replay and grant expiry under the new label.

## Regenerate

```sh
/usr/bin/python3 test-vectors/v3/generate.py
```

The generator reuses the v2 reference implementation and is self-checking:
it exits 0 only when every vector matches its reference.
