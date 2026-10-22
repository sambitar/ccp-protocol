#!/usr/bin/env python3
"""Cross-language interop: generate in each SDK, verify in the other, and
compare the wires byte for byte.

Usage: /usr/bin/python3 conformance/interop.py [--skip-build]
"""

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TS_DIR = os.path.join(ROOT, "sdk", "typescript")
PY_DIR = os.path.join(ROOT, "sdk", "python")


def run(command, cwd):
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True)


def main():
    skip_build = "--skip-build" in sys.argv[1:]
    if not skip_build:
        build = run(["npm", "run", "build"], TS_DIR)
        if build.returncode != 0:
            print(build.stdout + build.stderr, file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory(prefix="ccp-interop-") as directory:
        ts_path = os.path.join(directory, "ts.json")
        py_path = os.path.join(directory, "py.json")
        steps = [
            ("ts generate", ["node", "conformance/interop.mjs", "generate",
                             ts_path], TS_DIR),
            ("py generate", [sys.executable, "conformance/interop.py",
                             "generate", py_path], PY_DIR),
            ("ts verify py", ["node", "conformance/interop.mjs", "verify",
                              py_path], TS_DIR),
            ("py verify ts", [sys.executable, "conformance/interop.py",
                              "verify", ts_path], PY_DIR),
        ]
        for label, command, cwd in steps:
            result = run(command, cwd)
            passed = result.returncode == 0
            print("%-14s %s" % (label, "ok" if passed else "FAILED"))
            if not passed:
                print(result.stdout, file=sys.stderr)
                print(result.stderr, file=sys.stderr)
                return 1

        with open(ts_path, encoding="utf-8") as handle:
            ts = json.load(handle)
        with open(py_path, encoding="utf-8") as handle:
            py = json.load(handle)

        ok = True
        for field in ("manifest_wire", "manifest_digest", "signal_wire",
                      "signal_signing_sha256"):
            same = ts[field] == py[field]
            print("%-24s %s" % (field + ":", "identical" if same
                                else "DIFFERENT"))
            ok = ok and same

        print("shared digest: %s" % ts["manifest_digest"])
        print("interop:", "ok" if ok else "FAILED")
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
