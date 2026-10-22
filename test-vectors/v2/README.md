# CCP v2 conformance vectors

`../*.json` is the frozen v1 contract. This directory is additive: it pins
the adversarial edges that v1 left implicit, without changing any v1 file.

Both the language-neutral runner (`conformance/run.py`) and each SDK test
suite load these files.

## Files

| File | Covers |
| --- | --- |
| `canonical-json.json` | astral-plane key sort, NFC key/value normalization, NFC key collisions, unpaired surrogates, `-0`, top-level-only `signature`, prototype-shaped keys, large integers, escaping |
| `validation.json` | expiry equality, limit equality, and check-order precedence |

Formats match v1: canonical cases carry `expected_canonical` or
`expect_error`; validation cases carry `grant`, `signal`, `signer`,
`context`, and `expected`.

`expect_error` values here are `duplicate`, `negative`, `float`, `constant`,
and `malformed`. `malformed` covers invalid JSON, a leading BOM, and
unpaired surrogates.

## Why these cases

- `cj2-001` distinguishes code-point sort from UTF-16 code-unit sort:
  `a` < `U+FFFF` < `U+1F600`.
- `cj2-004`/`cj2-005` enforce §25.1's rule that keys which differ only by
  normalization form are duplicates.
- `cj2-008`–`cj2-011` pin UTF-8 well-formedness: lone or mispaired
  surrogates are rejected; a valid pair becomes one literal character.
- `cj2-012`/`cj2-013` enforce that `signature` is last only in the
  top-level signed object; nested objects sort normally.
- `cj2-014` makes `__proto__` ordinary data, not a prototype mutation.
- `cj2-006`/`cj2-007` enforce the spec's explicit rejection of `-0`.
- `cj2-021` pins sorting of the NFC-normalized keys: `f` sorts before `é`
  even though the input key is `e` + combining acute.
- `v2-001`/`v2-002` pin `now >= expires_at` at equality for both grant and
  request expiry.
- `v2-004`/`v2-005` pin both sides of the limit boundary.
- `v2-007`–`v2-014` pin the §10.3 check order when two failures coincide.

## Regenerate

```sh
/usr/bin/python3 test-vectors/v2/generate.py
```

The generator is self-checking: it exits 0 only when every vector matches
its embedded reference. Do not regenerate after a release unless a vector is
objectively wrong; record any change here.
