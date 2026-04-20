# clang-format — CI-matching invocation

**Last updated:** 2026-04-20
**Type:** Pattern
**Status:** Active

## Description

Once CI is wired, the `check-format` job will run clang-format over the full source tree. Local pre-commit runs must use **exactly the same command** as CI, or local passes will be followed by CI failures on files the local run never touched.

This pattern records the canonical command so that when CI comes online it can be copy-pasted into the workflow, and so that local runs stay in sync.

## Context

Applies to every session that touches `.h`, `.hpp`, `.c`, `.cpp`, or `.rs` files under `kernel/`, `drivers/`, `subsystems/`, or `userland/`. ASM files (`.asm`, `.s`) are not covered by clang-format — check them by eye or via a dedicated linter later.

---

## Wrong

```bash
find kernel drivers subsystems userland \
  \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | head -50 \
  | xargs clang-format --dry-run --Werror
```

`head -50` caps the input to 50 files. Locally this passes while leaving thousands of files unchecked. CI runs without `head -50` and immediately fails.

## Right — the command CI will run

```bash
find kernel drivers subsystems userland \
  \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | xargs clang-format --dry-run --Werror
```

Omit `head -N`. Include every C/C++ directory that will ever ship code.

## Fix formatting in place

```bash
find kernel drivers subsystems userland \
  \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | xargs clang-format -i
```

## Rules

- Never use `head -N` in a format check command. If the argv is too long, use `xargs -n 500` to batch instead.
- `--Werror` is required — without it, `--dry-run` only reports diffs and exits 0.
- `.clang-format` at the repo root is the source of truth. Don't pass `--style=...` explicitly.
- Generated files (compiled assembly, linker scripts, build-time stubs) must live outside the directories listed above, or be opted out of formatting through an explicit ignore mechanism once we have one.

## When new top-level directories are added

If the tree grows a new top-level directory that contains C/C++ (e.g. `tests/`, `tools/harness/`), add it to the `find` roots **in both this entry and in CI at the same time**. Otherwise CI and local will drift.

## See also

- [workflow-patterns.md](workflow-patterns.md) — pre-commit flow, where format-check is step 1.
- [build-optimizations.md](build-optimizations.md) — `--parallel $(nproc)` for the subsequent build step.
- Parent project guide: `CLAUDE.md` → "Pre-commit checks" → "Code changes" section.
