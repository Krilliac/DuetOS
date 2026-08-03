#!/usr/bin/env python3
"""Reject GitHub Actions expressions that use a context unavailable at job level.

WHY
    A job-level key (`env`, `if`, `runs-on`, `name`, `concurrency`,
    `timeout-minutes`) may only reference the contexts GitHub makes
    available before a runner is assigned. `runner.*`, `steps.*`,
    `job.*`, `env.*` and `hashFiles()` are step-scoped; using one at job
    level is not a warning — GitHub refuses to parse the whole workflow
    and the run dies as a 0-second `startup_failure` with no jobs and no
    log, which reads like an infrastructure blip rather than a syntax
    error.

    This bit on 2026-08-03: `release.yml` gained
    `env: CARGO_HOME: ${{ runner.temp }}/...` on two jobs, which silently
    disabled the entire release-channels workflow. PyYAML parses the file
    happily, so no local YAML check catches it. Only a push does — and
    then only if you notice a 0s run among the real failures.

USAGE
    python tools/test/check-workflow-contexts.py
    python tools/test/check-workflow-contexts.py --dir .github/workflows

EXIT CODES
    0  every job-level expression uses an allowed context
    1  at least one invalid reference (printed with file/job/key)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

# Contexts and functions legal in a job-level expression. `runner`,
# `steps`, `job` and `hashFiles` are deliberately absent: they are only
# bound once a runner has picked the job up.
ALLOWED = {
    "github", "needs", "strategy", "matrix", "vars", "inputs", "secrets",
    "always", "success", "failure", "cancelled",
    "contains", "fromJSON", "format", "join", "toJSON",
    "startsWith", "endsWith",
}

JOB_LEVEL_KEYS = ("env", "if", "runs-on", "name", "concurrency", "timeout-minutes", "continue-on-error")

EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)
CONTEXT = re.compile(r"\b([a-zA-Z_]\w*)\s*[.(]")


def check_file(path: Path) -> list[str]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{path}: YAML did not parse: {exc}"]

    if not isinstance(doc, dict):
        return []

    problems = []
    for job, body in (doc.get("jobs") or {}).items():
        if not isinstance(body, dict):
            continue
        for key in JOB_LEVEL_KEYS:
            value = body.get(key)
            if value is None:
                continue
            for expr in EXPR.findall(str(value)):
                for ctx in CONTEXT.findall(expr):
                    if ctx not in ALLOWED:
                        problems.append(
                            f"{path}: jobs.{job}.{key} references '{ctx}', "
                            f"which is not available at job level"
                        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", default=".github/workflows",
                        help="directory of workflow YAML (default .github/workflows)")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2] / args.dir
    files = sorted(list(root.glob("*.yml")) + list(root.glob("*.yaml")))
    if not files:
        print(f"no workflow files under {root}", file=sys.stderr)
        return 1

    problems = [p for f in files for p in check_file(f)]
    for problem in problems:
        print(problem)

    print(f"checked {len(files)} workflow file(s): "
          f"{'OK' if not problems else str(len(problems)) + ' problem(s)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
