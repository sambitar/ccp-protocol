#!/usr/bin/env bash
# Cross-compile the kernel shared library for Android ABIs (JNA loads it).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
NDK="${ANDROID_NDK_HOME:-$HOME/Android/Sdk/ndk/27.1.12297006}"
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
OUT="$HERE/jniLibs"

if [[ ! -d "$TOOLCHAIN" ]]; then
  echo "NDK toolchain not found at $TOOLCHAIN" >&2
  exit 1
fi

mkdir -p "$OUT/arm64-v8a" "$OUT/x86_64"

RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384" \
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/aarch64-linux-android21-clang" \
  cargo build --release --target aarch64-linux-android \
  --manifest-path "$ROOT/kernel/Cargo.toml"

RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384" \
CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$TOOLCHAIN/x86_64-linux-android21-clang" \
  cargo build --release --target x86_64-linux-android \
  --manifest-path "$ROOT/kernel/Cargo.toml"

cp "$ROOT/kernel/target/aarch64-linux-android/release/libccp_kernel.so" \
   "$OUT/arm64-v8a/libccp_kernel.so"
cp "$ROOT/kernel/target/x86_64-linux-android/release/libccp_kernel.so" \
   "$OUT/x86_64/libccp_kernel.so"

file "$OUT/arm64-v8a/libccp_kernel.so" "$OUT/x86_64/libccp_kernel.so"
