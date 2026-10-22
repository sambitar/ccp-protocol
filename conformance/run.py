#!/usr/bin/env python3
"""Run both SDK conformance harnesses over v1 and v2 and compare results.

Usage: /usr/bin/python3 conformance/run.py [--skip-build]
"""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TS_DIR = os.path.join(ROOT, "sdk", "typescript")
PY_DIR = os.path.join(ROOT, "sdk", "python")
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
        ts_summary = parse_output(ts, "typescript")
        py_summary = parse_output(py, "python")
        if ts_summary is None or py_summary is None:
            ok = False
            continue

        for suite in sorted(set(ts_summary) | set(py_summary)):
            t = ts_summary.get(suite)
            p = py_summary.get(suite)
            if t is None or p is None:
                print("%-18s %-16s missing in one SDK" % (directory, suite))
                ok = False
                continue

            t_ids = [failure["id"] for failure in t["failures"]]
            p_ids = [failure["id"] for failure in p["failures"]]
            agree = (
                t["passed"] == p["passed"]
                and t["failed"] == p["failed"]
                and t_ids == p_ids
            )
            print(
                "%-18s %-16s ts %d/%d  py %d/%d  %s"
                % (
                    directory,
                    suite,
                    t["passed"],
                    t["passed"] + t["failed"],
                    p["passed"],
                    p["passed"] + p["failed"],
                    "agree" if agree else "DISAGREE",
                )
            )
            if not agree or t["failed"] or p["failed"]:
                ok = False
                for label, entry in (("ts", t), ("py", p)):
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
