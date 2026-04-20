# Git Rebase Conflict Resolution

**Last updated:** 2026-04-20
**Type:** Pattern
**Status:** Active

## Description

Rebase-time conflicts in this repo cluster around a handful of predictable file types. This entry documents the default resolution for each.

## Context

Applies when running `git rebase origin/main` before commit/push (per the Session Start workflow in `CLAUDE.md`). Most early-stage conflicts will be in docs or context files, not source — at least until the kernel tree has real code.

---

## Rule 1 — Auto-generated sections (future)

Once we have doc-generation scripts, certain blocks will be delimited by markers like:

```
<!-- AUTO:stats -->
…live content produced by a script…
<!-- /AUTO:stats -->
```

When two branches edit these sections independently, **always take the upstream side** — your local change will be rewritten by the next generation run, so there's nothing to preserve.

```bash
# From the conflict state
git checkout --theirs path/to/file.md
git add path/to/file.md
git rebase --continue

# Then regenerate to get the correct counts for HEAD
# (once the generator exists)
# tools/docs/regen.sh
```

Until those scripts exist, this rule is aspirational — there are no AUTO: sections in the tree yet.

## Rule 2 — Stat counters in README / CLAUDE.md / `.claude/index.md`

These files hold status snapshots ("Current Project State", test counts, etc.). When they conflict during rebase:

- If upstream's snapshot is newer, take upstream.
- If your branch changed a specific number for a real reason, keep your side for that number only, then re-read the surrounding context to make sure the snapshot still reads coherently.

## Rule 3 — Source code conflicts

Always resolve manually. Do **not** use `--theirs` / `--ours` blindly on `.h`, `.c`, `.cpp`, `.rs`, or `CMakeLists.txt` files — a wrong pick silently drops functionality.

In a kernel tree this is especially hazardous: a silently-dropped lock release or page-table invalidation can corrupt state without any immediate symptom.

## Rule 4 — Syscall tables and ABI-defining headers

Treat `kernel/syscall/*` dispatch tables and any public-ABI header (once they exist) as particularly hazardous merge targets. A conflict that "just rearranges lines" can silently shift syscall numbers. Always:

1. Resolve manually — never use `--theirs`/`--ours`.
2. After resolving, re-read the resulting file top-to-bottom and verify the numeric order.
3. If in doubt, regenerate the table from whatever source of truth we've chosen (e.g. a `.tbl` file) rather than hand-merging it.

## Pre-rebase safety check

Before starting, confirm how much you're about to pull in:

```bash
git fetch origin main
git log --oneline HEAD..origin/main | wc -l
```

See [build-optimizations.md](build-optimizations.md) for the branch-delta thresholds that tell you whether to expect conflicts.

## Post-rebase cleanup

```bash
# Once doc generators exist, re-run them so every snapshot matches the rebased HEAD.
# For now, just re-read README and .claude/index.md to confirm they still make sense.

# If anything changed, amend the rebase tip rather than adding a new commit
git diff --quiet || git commit -am "docs: refresh snapshots after rebase"
```

## See also

- [build-optimizations.md](build-optimizations.md) — pre-rebase branch-delta check.
- [workflow-patterns.md](workflow-patterns.md) — the full rebase → verify → push flow.
- Parent project guide: `CLAUDE.md` → "Git Sync Workflow" section.
