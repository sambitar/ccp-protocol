# Release checklist

Current version: **0.5.0 (draft)**. All three registries are published at
0.5.0.

> Local artifacts below were built from a clean working tree. Rebuild
> everything from the tagged commit before any publish; the working tree may
> still change after this record.

## Status

| Registry | Artifact | Local check | Publish status |
| --- | --- | --- | --- |
| npm (`ccp-core`) | `ccp-core-0.5.0.tgz` — 48 files, 29.4 kB | `npm pack --dry-run`; contains only `dist/`, `README.md`, `package.json` | **Published 0.5.0** |
| PyPI (`ccp-protocol`) | `ccp_protocol-0.5.0-py3-none-any.whl` — 29,537 bytes | wheel built; includes `ccp.adapters` and `ccp.stores_sqlite` | **Published 0.5.0** |
| crates.io (`ccp-kernel`) | `ccp-kernel-0.5.0.crate` — 17 files, 18.6 KiB compressed | `cargo package` verified the build | **Published 0.5.0** |
| Maven Central | none | — | Not prepared: no Gradle artifact; the JVM binding is a script + JNA |
| SwiftPM | none | — | Deferred: Swift toolchain; Apple targets need Xcode |
| Google Maven (AAR) | Android `.so` only | arm64 + x86_64 ELF verified | Blocked: Android SDK/Gradle for an AAR |

Local artifact hashes (crate line is the published registry checksum):

```
9237bc4545d9fba3a4efb32e0c5d4454ec7b5878de41240bd71afd6c513d667a  ccp-core-0.5.0.tgz
136ecad147841be55390dda2b6b11b03b6ec69a2f2ace7ed107a4974e862032a  ccp_protocol-0.5.0-py3-none-any.whl
da704d7bccbab01d589d9840d80f3e608b97d40227a288f5f67fdf364e5de4f8  ccp-kernel-0.5.0.crate
```

## Blockers

1. **License.** The repository is Apache-2.0 (`LICENSE`, `NOTICE`), and the
   npm, PyPI, and crates.io manifests declare it. A separate specification
   licence may be adopted later (§26.8).
2. **Registry credentials.** All three registries are published at 0.5.0.
3. **Clean-tree release.** Rebuild from the tagged commit; do not ship the
   working tree.
4. **Independent review** before high-impact capabilities (§17).
5. **Maven/Swift/Android app packaging** need Gradle, Swift, and the Android
   SDK respectively.

## Build artifacts

### npm

```sh
cd sdk/typescript
npm run build
npm pack --dry-run          # inspect
npm pack --pack-destination /tmp
# npm publish --access public   (after login and version review)
```

`files` limits the tarball to `dist/`, `README.md`, and `package.json`.
`engines.node` is `>=18`.

### PyPI

```sh
/usr/bin/python3 -m pip wheel --no-deps --no-build-isolation \
  --wheel-dir /tmp/ccp-wheel sdk/python
# python -m twine upload /tmp/ccp-wheel/*.whl   (after token + license)
```

The wheel contains `ccp/` and `ccp/adapters/`. Optional extras: `fastapi`,
`mcp`, `dev`.

### crates.io

```sh
cargo package --allow-dirty --manifest-path kernel/Cargo.toml
# cargo publish --manifest-path kernel/Cargo.toml   (after token + license)
```

`cargo package` warns about missing documentation, homepage, and repository
fields. Those are metadata and do not block a publish.

### Go / Kotlin / Android

These are source integrations, not registry packages:

- Go: consumers import `bindings/go/ccp` and build the kernel archive for
  their platform.
- Kotlin/JVM: `bindings/kotlin/build.sh` compiles against JNA and the shared
  library. A Maven artifact requires a Gradle project.
- Android: `bindings/kotlin/android/build-so.sh` produces the `.so` files; an
  AAR requires the Android SDK/Gradle.

## Publish

PyPI `ccp-protocol` **0.5.0**, npm `ccp-core` **0.5.0**, and crates.io
`ccp-kernel` **0.5.0** are published.

1. Rebuild from the tagged commit with the `Build artifacts` commands above;
   do not publish a working-tree tarball.
2. Confirm the artifact hashes match the ones recorded for the tag.

### npm

```sh
cd sdk/typescript
npm login                 # account uses 2FA with a security key
npm publish --access public
```

`npm publish` prints a browser authentication URL. Complete the security-key
flow, or use an **Automation** access token (which bypasses the OTP prompt)
for non-interactive or CI publishes. The package is unscoped (`ccp-core`), so
no organization or scope ownership is required.

### PyPI

```sh
/usr/bin/python3 -m pip install --upgrade twine
/usr/bin/python3 -m twine upload /tmp/ccp-wheel/*.whl
# credentials: TWINE_USERNAME=__token__ TWINE_PASSWORD=<pypi-token>
```

### crates.io

```sh
cargo publish --manifest-path kernel/Cargo.toml
# credentials: cargo login <crates-io-token>
```

After publishing, install each artifact in a clean environment and run the
quickstarts (see `Clean-environment verification`).

## Release checklist

- [x] Choose a license and add `LICENSE` (Apache-2.0)
- [x] Bump the version in `sdk/typescript/package.json`,
      `sdk/python/pyproject.toml`, `kernel/Cargo.toml`
- [ ] Tag the commit; rebuild all artifacts from the tag
- [ ] Run the full gate (below) on the tag
- [x] Clean-environment verification (packed npm tarball, wheel, crate)
- [x] Publish PyPI (`ccp-protocol` 0.5.0)
- [x] Publish npm (`ccp-core` 0.5.0)
- [x] Publish crates.io (`ccp-kernel` 0.5.0)
- [x] Adopt transport and namespace profiles normatively (§25.7, §19.2.1)
- [x] Adopt the identity and admission profile (§25.8)
- [ ] Install each package in a clean container and run the quickstarts:
      `docs/guides/{web,provider,agent,runtime}.md`
- [ ] Verify the installed packages include the expected files
      (`dist/adapters/*`, `ccp/adapters/*`, kernel sources)
- [ ] Announce the draft with the security limitations from `SECURITY.md`

## Full gate (run on the tag)

```sh
cargo test --manifest-path kernel/Cargo.toml
cargo clippy --manifest-path kernel/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path kernel/Cargo.toml --check
cargo build --release --manifest-path kernel/Cargo.toml
cargo build --release --target wasm32-unknown-unknown --manifest-path kernel/Cargo.toml
cc -Wall -Wextra -I kernel/include \
   kernel/c-tests/smoke.c kernel/target/release/libccp_kernel.a \
   -lpthread -ldl -lm -o /tmp/ccp-smoke && /tmp/ccp-smoke
node bindings/js/test.mjs
/usr/bin/python3 conformance/run.py --skip-build
/usr/bin/python3 conformance/interop.py --skip-build
(cd sdk/typescript && npm run typecheck && npx vitest run)
(cd sdk/python && /usr/bin/python3 -m unittest discover -s tests)
(cd bindings/go && go test ./...)
bindings/kotlin/build.sh test
npm --prefix sdk/typescript pack --dry-run
/usr/bin/python3 -m pip wheel --no-deps --no-build-isolation --wheel-dir /tmp/ccp-wheel sdk/python
cargo package --allow-dirty --manifest-path kernel/Cargo.toml
```

Expected: all suites green; 51 v1 + 38 v2 + 8 v3 + 39 v4 vectors (v4 is
TypeScript and Python only); WASM 97/97; Kotlin 109/109; C smoke ok; interop
wires identical; all three packages build.

## Clean-environment verification (done)

Performed from the packaged artifacts, not the source tree:

1. Empty Node project with the packed 0.5.0 tarball, and again by installing
   `ccp-core@0.5.0` from npm: the core runtime, `ccp-core/node` SQLite stores,
   an Express HTTP round trip, and an MCP bridge tool call all passed.
2. Fresh virtualenv with `ccp-protocol==0.5.0` from PyPI and FastAPI: the
   core runtime, `ccp.stores_sqlite`, `GET /manifest`, and a `POST /ccp`
   round trip passed.
3. `cargo new` project depending on `ccp-kernel = "0.5.0"` from crates.io:
   parsed and canonically re-serialized a document.

Commands used (clean shell, from the repository root):

```sh
# Node
npm install --prefix /tmp/ccp-npm-verify-050 /tmp/ccp-release/ccp-core-0.5.0.tgz express
node /tmp/ccp-npm-verify-050/smoke.mjs

# Python
python3 -m venv /tmp/ccp-verify-py-050
/tmp/ccp-verify-py-050/bin/pip install 'ccp-protocol==0.5.0' fastapi httpx
/tmp/ccp-verify-py-050/bin/python /tmp/ccp-verify-py-050/smoke.py

# Rust
cargo new /tmp/ccp-crate-verify-050 --bin --vcs none
# add: ccp-kernel = "0.5.0"
cargo run --manifest-path /tmp/ccp-crate-verify-050/Cargo.toml
```

The MCP path was exercised through the packaged `ccp-core/mcp` bridge
(`createMcpServer` + `callTool`), not the repository example.
