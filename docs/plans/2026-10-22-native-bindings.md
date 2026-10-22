# Native Bindings Plan (Go, Kotlin/JVM, Swift)

**Goal:** reach Go, JVM/Android, and Apple-platform developers through the vetted Rust kernel, with each binding running the full vector suite and a requester example.

**Architecture:** Every binding calls the kernel's string-based C ABI (`kernel/include/ccp.h`) and shares one contract: allocate input, call the operation, parse the JSON envelope, free. The kernel is built once per platform (staticlib for Go/Swift, shared library for JNA, cross-compiled `.so` for Android).

**Toolchain reality (this host):** Ubuntu 24.04 x86_64. Go 1.23.6 and JDK 21 are installed. Kotlin 2.1.20 and Swift 6.0.3 for Linux are installable and are installed under `~/.local`, not committed. The Android NDK 27.1 is installed. Xcode and an Android SDK/Gradle are not available, so iOS/macOS and an installable AAR cannot be built here; those artifacts are documented and their platform-independent code is tested on Linux/JVM.

**Status (2026-10-22):** Tasks 1 and 2 are complete and verified: Go passes
89/89 vectors and its requester example runs; Kotlin/JVM passes 109 checks
and its example runs; Android arm64/x86_64 shared libraries cross-build.
Task 3 (Swift) is deferred: the Linux toolchain was not installed in this
session, and Apple targets require Xcode. The Swift task below remains the
plan.

**Spec:** `CCP_Working_Draft_v0.5.md` §25.1–25.3. Contract: `test-vectors/` + `test-vectors/v2/`.

## Global Constraints

- Each binding must pass all **89** cases: canonical 18+21, validation 18+17, state 10, Ed25519 3+2.
- Requester examples sign a manifest and a signal; they do not implement protocol logic themselves.
- Downloaded toolchains, jars, and build outputs never enter the repository.
- Binding APIs are idiomatic per language; wire fields stay snake_case.
- Nothing in `kernel/`, `sdk/`, or `test-vectors/` changes except the Android build docs if needed.
- Commit only when the user asks.

## Shared result contract

Every call returns `0`/`1` and a JSON envelope in the result buffer:

```json
{"ok":true,"value":…}
{"ok":false,"error":"duplicate"}
```

Bindings expose the value and the error code separately; the envelope type is internal.

## File map

| Path | Responsibility |
| --- | --- |
| `bindings/go/go.mod` | local module |
| `bindings/go/ccp/ccp.go` | cgo bindings and high-level API |
| `bindings/go/ccp/vectors_test.go` | 89 vector cases |
| `bindings/go/examples/requester/main.go` | manifest + signal example |
| `bindings/go/README.md` | build, link, test |
| `bindings/kotlin/build.sh` | fetch JNA/Gson, compile, run tests |
| `bindings/kotlin/src/main/kotlin/ccp/Kernel.kt` | JNA interface + API |
| `bindings/kotlin/src/test/kotlin/ccp/VectorsTest.kt` | vector runner |
| `bindings/kotlin/examples/Requester.kt` | requester example |
| `bindings/kotlin/android/build-so.sh` | NDK cross-build for arm64/x86_64 |
| `bindings/kotlin/README.md` | JVM and Android usage |
| `bindings/swift/build.sh` | toolchain check, header copy, test/run |
| `bindings/swift/Package.swift` | system library + library + executable |
| `bindings/swift/Sources/CCcpKernel/module.modulemap` | C module map |
| `bindings/swift/Sources/CcpKernel/Kernel.swift` | Swift API |
| `bindings/swift/Tests/CcpKernelTests/VectorsTests.swift` | XCTest vectors |
| `bindings/swift/Sources/Requester/main.swift` | requester example |
| `bindings/swift/README.md` | Linux build and Apple-platform notes |

`.gitignore` gains `.build/`, Kotlin `out/` and `lib/`, and the copied Swift header.

---

### Task 1: Go binding

- [ ] `bindings/go/go.mod` with `module ccp/bindings/go`, `go 1.23`.
- [ ] cgo directives pointing at `../../../kernel/{include,target/release}`; static link (`-lccp_kernel -lpthread -ldl -lm`).
- [ ] `invoke` helper: alloc, copy, call by op code, read `ccp_result_ptr/len`, free, unmarshal.
- [ ] API: `Canonicalize`, `Decide`, `NextState`, `Sign`, `Verify`, `SignDocument`; each returns `(value, errorCode)`.
- [ ] Tests: read v1+v2 JSON with `encoding/json`; use `json.RawMessage` for grant/signal so the kernel sees the vector bytes; run all 89 cases.
- [ ] Example: sign a manifest and a signal with seed `00..1f`, print both wires; verify the signal with the kernel.
- [ ] Verify: `cd bindings/go && go test ./...` and `go run ./examples/requester`.

### Task 2: Kotlin/JVM binding

- [ ] Install Kotlin 2.1.20 under `~/.local/kotlin` (compiler zip from GitHub).
- [ ] `build.sh` downloads pinned `jna` and `gson` jars into `bindings/kotlin/lib/` if missing, compiles with `kotlinc`, and runs the test runner with `-Djna.library.path=…/kernel/target/release`.
- [ ] `Kernel.kt`: JNA `Library` interface (`size_t` as `NativeLong`, `int32_t` as `Int`), plus `canonicalize`, `decide`, `nextState`, `sign`, `verify`, `signDocument` returning a sealed result.
- [ ] `VectorsTest.kt`: plain `main` runner for all 89 cases; exits non-zero on failure. Use Gson for vector files and envelopes.
- [ ] `Requester.kt`: signs a manifest and signal, prints and verifies them.
- [ ] Verify: `bindings/kotlin/build.sh test` and `build.sh example`.
- [ ] Android: `android/build-so.sh` cross-compiles the kernel for `aarch64-linux-android` and `x86_64-linux-android` using NDK clang; document copying the `.so` into `jniLibs` and that JNA loads it. Build and confirm the files exist.

### Task 3: Swift package

- [ ] Install Swift 6.0.3 for Ubuntu 24.04 under `~/.local/swift`; verify `swift --version`.
- [ ] `build.sh` copies `kernel/include/ccp.h` into `Sources/CCcpKernel/` (gitignored) and runs `swift test`/`swift run` with `LIBRARY_PATH` set to the kernel release directory.
- [ ] `module.modulemap` exposes the C header as `CCcpKernel` and links `ccp_kernel`.
- [ ] `Kernel.swift`: `UInt8` buffer handling, `withUnsafeBytes`, `Data` → result, `JSONSerialization` envelopes; API mirroring the other bindings.
- [ ] `VectorsTests.swift`: XCTest over all 89 cases (or a plain executable if XCTest discovery is problematic).
- [ ] `Requester` executable: sign and verify a manifest/signal.
- [ ] Verify: `swift test` and `swift run Requester` on Linux. Document that iOS/macOS requires Xcode and that the same package builds there.

### Task 4: Docs and full gate

- [ ] Binding READMEs: prerequisites, build, test, API sketch, platform notes.
- [ ] `.gitignore`: `.build/`, `bindings/kotlin/lib/`, `bindings/kotlin/out/`, `bindings/swift/Sources/CCcpKernel/ccp.h`, Android `.so` outputs.
- [ ] Gate:
  - `cd bindings/go && go test ./...`
  - `bindings/kotlin/build.sh test`
  - `LIBRARY_PATH=… swift test` in `bindings/swift`
  - `cargo test --manifest-path kernel/Cargo.toml`
  - `node bindings/js/test.mjs`
  - `conformance/run.py --skip-build` and `conformance/interop.py --skip-build`
- [ ] Report any platform limitation explicitly rather than claiming an untested target.

## Self-review

- All three bindings consume the same ABI and vectors; no protocol logic is duplicated.
- Toolchain gaps are handled by installing under `~/.local` and documenting Apple/Android limits.
- Each task ends with a runnable command and an expected pass.
