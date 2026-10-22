# CCP — Go binding

Go bindings over the portable kernel's C ABI. The binding only marshals
inputs, calls the kernel, and parses the JSON envelope; protocol logic stays
in Rust.

## Prerequisites

Build the kernel archive for the host:

```sh
cargo build --release --manifest-path kernel/Cargo.toml
```

## Test and run

```sh
cd bindings/go
go test ./...
go run ./examples/requester
```

`go test` runs all 89 v1 + v2 vectors: canonical, validation, state machine,
and Ed25519.

## API

```go
import "ccp/bindings/go/ccp"

canonical, err := ccp.Canonicalize(`{"b":1,"a":2}`)
decision, err := ccp.Decide(ccp.DecisionInput{ /* grant, signal, … */ })
state, err := ccp.NextState(&from, "validate_ok")
signed, err := ccp.Sign(seedHex, messageHex)
ok, err := ccp.Verify(publicKeyHex, messageHex, signatureField)
document, err := ccp.SignDocument(documentJSON, seedHex)
```

Protocol rejections are `*ccp.ProtocolError`; use `err.(*ccp.ProtocolError).Code`
to read the §10.4 code or canonical error (`duplicate`, `negative`, …).

`DecisionInput` passes `Grant` and `Signal` as `json.RawMessage` so the
kernel sees the exact vector bytes, and `Counters` as `map[string]json.Number`
to preserve integer precision.

## Linking

`ccp.go` uses cgo with `-L${SRCDIR}/../../../kernel/target/release` and links
`libccp_kernel.a` statically (`-lpthread -ldl -lm`). Rebuild the kernel for
each OS/architecture you target; the release archive is not portable across
them.
