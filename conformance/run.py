#!/usr/bin/env python3
"""Run the TypeScript, Python, and Rust conformance harnesses over v1-v5.

Usage: /usr/bin/python3 conformance/run.py [--skip-build]
"""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TS_DIR = os.path.join(ROOT, "sdk", "typescript")
PY_DIR = os.path.join(ROOT, "sdk", "python")
RUNTIME_MANIFEST = os.path.join(ROOT, "runtime", "Cargo.toml")
VECTOR_DIRS = ["test-vectors", os.path.join("test-vectors", "v2"),
               os.path.join("test-vectors", "v3"),
               os.path.join("test-vectors", "v4"),
               os.path.join("test-vectors", "v5")]


def run(command, cwd):
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True)


def parse_output(result, label):
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("%s produced no JSON" % label, file=sys.stderr)
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return None


def suite_ids(entry):
    return [failure["id"] for failure in entry["failures"]]


def main():
    skip_build = "--skip-build" in sys.argv[1:]
    if not skip_build:
        build = run(["npm", "run", "build"], TS_DIR)
        if build.returncode != 0:
            print(build.stdout + build.stderr, file=sys.stderr)
            return 1

    ok = True
    for directory in VECTOR_DIRS:
        path = os.path.join(ROOT, directory)
        ts = run(["node", "conformance/run.mjs", path], TS_DIR)
        py = run([sys.executable, "conformance/run.py", path], PY_DIR)
        rs = run([
            "cargo", "run", "--quiet", "--bin", "conformance",
            "--manifest-path", RUNTIME_MANIFEST, "--", path,
        ], ROOT)
        summaries = [
            ("ts", parse_output(ts, "typescript")),
            ("py", parse_output(py, "python")),
            ("rs", parse_output(rs, "rust")),
        ]
        if any(summary is None for _, summary in summaries):
            ok = False
            continue

        suites = set()
        for _, summary in summaries:
            suites.update(summary)
        for suite in sorted(suites):
            entries = []
            missing = False
            for label, summary in summaries:
                entry = summary.get(suite)
                if entry is None:
                    print("%-18s %-16s missing in %s" % (directory, suite, label))
                    missing = True
                entries.append((label, entry))
            if missing:
                ok = False
                continue

            baseline = entries[0][1]
            agree = all(
                entry["passed"] == baseline["passed"]
                and entry["failed"] == baseline["failed"]
                and suite_ids(entry) == suite_ids(baseline)
                for _, entry in entries[1:]
            )
            counts = "  ".join(
                "%s %d/%d" % (
                    label,
                    entry["passed"],
                    entry["passed"] + entry["failed"],
                )
                for label, entry in entries
            )
            print(
                "%-18s %-16s %s  %s"
                % (directory, suite, counts, "agree" if agree else "DISAGREE")
            )
            if not agree or any(entry["failed"] for _, entry in entries):
                ok = False
                for label, entry in entries:
                    for failure in entry["failures"]:
                        print(
                            "  %s %s expected=%r got=%r"
                            % (
                                label,
                                failure["id"],
                                failure["expected"],
                                failure["got"],
                            )
                        )

    print("conformance:", "ok" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
