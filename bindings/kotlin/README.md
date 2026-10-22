# CCP — Kotlin/JVM binding

JVM bindings over the portable kernel's C ABI, using JNA. The binding
marshals JSON, calls the kernel, and returns a typed result; protocol logic
stays in Rust.

## Prerequisites

- JDK 21
- Kotlin 2.1 compiler (`KOTLIN_HOME`, default `~/.local/kotlin`)
- Kernel shared library:

```sh
cargo build --release --manifest-path kernel/Cargo.toml
```

`build.sh` downloads pinned JNA 5.15.0 and Gson 2.11.0 into `lib/` if
missing (both directories are gitignored).

## Test and run

```sh
bindings/kotlin/build.sh test
bindings/kotlin/build.sh example
```

`test` runs all 89 v1 + v2 vectors with field-level assertions (109 checks).
`example` signs a manifest and a signal and prints both wires.

## API

```kotlin
import ccp.Ccp
import ccp.KernelResult
import com.google.gson.JsonObject

when (val result = Ccp.canonicalize("""{"b":1,"a":2}""")) {
    is KernelResult.Ok -> println(result.value)
    is KernelResult.Failure -> println(result.code)
}

Ccp.decide(inputJsonObject)
Ccp.nextState(from = "authorized", event = "no_confirmation")
Ccp.sign(seedHex, messageHex)
Ccp.verify(publicKeyHex, messageHex, signatureField)
Ccp.signDocument(documentJson, seedHex)
```

`KernelResult.Failure.code` carries the §10.4 code or canonical error
(`duplicate`, `negative`, …). `decide` takes a Gson `JsonObject`; numbers
parsed from JSON keep their original literal, so integer precision is
preserved.

## Android

Cross-compile the kernel for the device ABIs:

```sh
bindings/kotlin/android/build-so.sh
```

This writes `android/jniLibs/arm64-v8a/libccp_kernel.so` and
`android/jniLibs/x86_64/libccp_kernel.so`, built with NDK clang and 16 KB
page alignment. In an app module:

- Add the JNA dependency (`net.java.dev.jna:jna:5.15.0@aar`).
- Package `jniLibs/` as usual (`sourceSets["main"].jniLibs.srcDirs`).
- JNA loads `ccp_kernel` from the app's native library directory; no
  `jna.library.path` is needed on device.

The JVM binding code is unchanged between desktop and Android. An Android
app/AAR is not built in this repository because the Android SDK/Gradle
toolchain is not installed here.
