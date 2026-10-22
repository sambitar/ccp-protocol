#!/usr/bin/env bash
# Build the JVM binding and run either the vector suite or the example.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
KOTLIN_HOME="${KOTLIN_HOME:-$HOME/.local/kotlin}"
KOTLINC="$KOTLIN_HOME/bin/kotlinc"

if [[ ! -x "$KOTLINC" ]]; then
  echo "kotlinc not found at $KOTLINC; set KOTLIN_HOME" >&2
  exit 1
fi

LIB_DIR="$HERE/lib"
OUT_DIR="$HERE/out"
JNA_JAR="$LIB_DIR/jna-5.15.0.jar"
GSON_JAR="$LIB_DIR/gson-2.11.0.jar"

mkdir -p "$LIB_DIR" "$OUT_DIR"
if [[ ! -f "$JNA_JAR" ]]; then
  curl -fsSL -o "$JNA_JAR" \
    https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.15.0/jna-5.15.0.jar
fi
if [[ ! -f "$GSON_JAR" ]]; then
  curl -fsSL -o "$GSON_JAR" \
    https://repo1.maven.org/maven2/com/google/code/gson/gson/2.11.0/gson-2.11.0.jar
fi

CLASSPATH="$JNA_JAR:$GSON_JAR:$KOTLIN_HOME/lib/kotlin-stdlib.jar"
"$KOTLINC" -cp "$CLASSPATH" -d "$OUT_DIR" \
  "$HERE/src/main/kotlin/ccp/Kernel.kt" \
  "$HERE/src/test/kotlin/ccp/VectorsTest.kt" \
  "$HERE/examples/Requester.kt"

JAVA_OPTS=(
  "-Djna.library.path=$ROOT/kernel/target/release"
  "--enable-native-access=ALL-UNNAMED"
  "-cp"
  "$OUT_DIR:$CLASSPATH"
)

case "${1:-test}" in
  test)
    cd "$ROOT"
    java "${JAVA_OPTS[@]}" ccp.VectorsTestKt
    ;;
  example)
    cd "$ROOT"
    java "${JAVA_OPTS[@]}" ccp.RequesterKt
    ;;
  *)
    echo "usage: $0 [test|example]" >&2
    exit 2
    ;;
esac
