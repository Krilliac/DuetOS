# Git Workflow

> **Audience:** All contributors
>
> **Execution context:** Host (Linux dev machine)
>
> **Maturity:** Stable

## Overview

DuetOS uses a feature-branch workflow with `main` as the merge target.
Each Claude-driven session works on its own `claude/<slug>` branch.
Human-driven branches use whatever convention the contributor
prefers, but the merge target is always `main`.

## Session Start — Git Sync

Run this **before** every session start and **before** every
commit/push. The default upstream branch is `main`.

```bash
git fetch origin main
git log --oneline HEAD..origin/main | wc -l   # check if behind
git rebase origin/main                         # if behind, rebase
# If conflicts: resolve, git add <files>, git rebase --continue
```

## Rules

- **Never** commit or push while behind the base branch. Always
  rebase first.
- Prefer upstream changes for auto-generated content
  (`<!-- AUTO:* -->` sections in wiki pages, generated symbol tables).
- All Claude-driven development happens on the feature branch the
  harness checked out for the session (`claude/<slug>`). Merge target
  is `main`. Do not push to other branches without explicit
  permission.

## Pre-commit Checks

Run checks **appropriate to the files you changed**.

### Docs-only changes (`.md`, `docs/`, `.claude/`, `wiki/`)

Proofread. Run any doc generators that exist at the time:

```bash
docs/sync-wiki.sh sync          # refresh AUTO:* sections
tools/check-wiki-nav.sh         # validate sidebar
tools/check-wiki-quality.sh     # quality checks
```

### Code changes (`.h`, `.hpp`, `.c`, `.cpp`, `.rs`, `.S`,
`CMakeLists.txt`)

```bash
# 1. Format check
find kernel drivers subsystems userland \
  \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | xargs clang-format --dry-run --Werror 2>&1

# 2. Fix formatting (if step 1 fails)
find kernel drivers subsystems userland \
  \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | xargs clang-format -i

# 3. CMake configure
cmake --preset x86_64-release 2>&1 | tail -20

# 4. Build
cmake --build build --parallel $(nproc) 2>&1 | tail -30

# 5. Tests
cd build && ctest --output-on-failure && cd ..

# 6. QEMU smoke (when there's a kernel to boot)
tools/qemu/run.sh --headless --timeout 30 build/duetos.img
```

If any step fails, fix before committing. CI enforces clang-format on
every PR.

`.S` files are NOT formatted by `clang-format`. Never pass a `.S`
file to `clang-format -i` — it will parse it as C++ and mangle it.

## Post-PR Checks

After creating or pushing to a PR, **always** poll CI and fix failures
before moving on. Use the GitHub MCP tools available in the
harness — do not shell out to `gh`.

See `.claude/knowledge/github-api-pr-checks.md` for the polling
workflow.

## Conflict Resolution

For rebase conflicts, see `.claude/knowledge/git-rebase-conflicts.md`
— a curated list of conflict shapes seen in this repo and the
canonical resolution for each.

## Related Pages

- [Build System](Build-System.md)
- [Coding Standards](Coding-Standards.md)
- [Anti-Bloat Guidelines](Anti-Bloat-Guidelines.md)
- [QEMU Smoke Tests](QEMU-Smoke.md)
- [Contributing](../advanced/Contributing.md)
