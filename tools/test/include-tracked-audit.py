#!/usr/bin/env python3
#
# DuetOS tracked-include auditor.
#
# Every `#include "..."` in a tracked source file must name a file
# that is ALSO tracked. A tracked TU that includes an untracked
# header compiles perfectly for the session that authored both, and
# fails for everyone else the moment the commit lands without the
# header — a fresh clone has the includer and not the include.
#
# This is not hypothetical: CLAUDE_PARALLEL.md's fleet protocol
# forbids `git add -A`, so every commit stages an explicit path
# list, and a brand-new header is exactly the thing that list
# forgets. The failure is invisible to a local build (the file is
# sitting right there, untracked) and invisible to a reviewer
# reading the diff (the include line looks fine). Only CI on a
# clean checkout catches it — days later.
#
# What counts as a violation:
#   a tracked .c/.cc/.cpp/.h/.hpp file has `#include "X"`, X
#   resolves to a file that EXISTS in the working tree, that file
#   lives inside the repo, and `git ls-files` does not list it.
#
# Deliberately NOT a violation:
#   - An include that resolves nowhere on disk. Generated headers
#     (cbindgen output for the Rust crates, CMake-configured
#     headers) live in the build tree, which this auditor does not
#     search. Flagging them would make the gate cry wolf.
#   - An include resolving to a git-ignored file — that is a
#     generated artefact, legitimately untracked.
#   - `#include <...>` — angle includes are toolchain/system
#     headers by convention here.
#
# Resolution mirrors the build's search order: the including
# file's own directory first (quoted-include semantics), then the
# `-I` roots the CMakeLists set (repo root, `kernel/` for the
# kernel and the host tests, the `tools/*/src` dirs).
#
# Usage:
#   tools/test/include-tracked-audit.py [--root <repo>] [--quiet]
#
# Exit status: 0 if every tracked source includes only tracked
# files, 1 otherwise. Human report AND ctest/CI gate — registered
# in tests/host/CMakeLists.txt as `include_tracked`.

import argparse
import os
import re
import subprocess
import sys

SRC_EXT = (".c", ".cc", ".cpp", ".h", ".hpp")

# Mirrors the `-I` roots the build sets: kernel/CMakeLists.txt adds
# `kernel/`, tests/host/CMakeLists.txt adds `kernel/` and its own
# directory, tools/vmm and tools/pkg add their `src/`.
INCLUDE_ROOTS = ("", "kernel", "tests/host", "tools/vmm/src", "tools/pkg/src")

INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"')


def git_lines(root, args):
    out = subprocess.run(
        ["git", "-C", root] + args, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    return [ln for ln in out.stdout.splitlines() if ln]


def tracked_set(root):
    return set(git_lines(root, ["ls-files"]))


def ignored_set(root, candidates):
    # One batched `check-ignore` instead of one process per path.
    if not candidates:
        return set()
    proc = subprocess.run(
        ["git", "-C", root, "check-ignore", "--stdin"],
        input="\n".join(sorted(candidates)) + "\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return {ln for ln in proc.stdout.splitlines() if ln}


def resolve(root, includer, target):
    """Return the repo-relative path `target` resolves to, or None."""
    bases = [os.path.dirname(includer)] + list(INCLUDE_ROOTS)
    for base in bases:
        rel = os.path.normpath(os.path.join(base, target)).replace(os.sep, "/")
        if rel.startswith(".."):
            continue  # escapes the repo — not ours to audit
        if os.path.isfile(os.path.join(root, rel)):
            return rel
    return None


def main(argv):
    ap = argparse.ArgumentParser(description="Assert tracked sources only include tracked files.")
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    ap.add_argument("--quiet", action="store_true", help="suppress the PASS line")
    args = ap.parse_args(argv[1:])
    root = os.path.abspath(args.root)

    tracked = tracked_set(root)
    if not tracked:
        print("[include-tracked] no tracked files under %s: is it a git repo?" % root, file=sys.stderr)
        return 1

    sources = sorted(f for f in tracked if f.endswith(SRC_EXT))
    suspects = []  # (includer, lineno, target, resolved)
    for src in sources:
        try:
            lines = open(os.path.join(root, src), encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            m = INCLUDE_RE.match(line)
            if not m:
                continue
            target = m.group(1)
            rel = resolve(root, src, target)
            if rel is None or rel in tracked:
                continue
            suspects.append((src, i + 1, target, rel))

    ignored = ignored_set(root, {s[3] for s in suspects})
    findings = [s for s in suspects if s[3] not in ignored]

    for includer, lineno, target, rel in findings:
        print('%s:%d: includes untracked file "%s" -> %s' % (includer, lineno, target, rel))

    if findings:
        print(
            "\n[include-tracked] %d tracked source(s) include an untracked file: "
            "stage it or the next clean checkout will not compile" % len(findings),
            file=sys.stderr,
        )
        return 1
    if not args.quiet:
        print("[include-tracked] PASS (%d tracked sources, every include tracked)" % len(sources), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
