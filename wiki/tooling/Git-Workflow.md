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

### Docs-only changes (`.md`, `docs/`, `wiki/`)

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
harness — do not shell out to `gh`. The polling workflow is:

1. List recent runs (`mcp__github__list_*` for the workflow).
2. Wait until the run completes (do not poll in tight loops; the
   webhook subscription described in `CLAUDE.md` arrives without a
   sleep).
3. On failure, read the failed step's log via the GitHub MCP and
   diagnose locally with the same commands the workflow runs.

## Conflict Resolution

For rebase conflicts, the canonical recipe is:

1. Stop on conflict; read each `<<<<<<< HEAD` block in turn.
2. **Auto-generated sections** (`<!-- AUTO:* -->`): always take the
   upstream side; they regenerate.
3. **Knowledge / wiki cross-references**: usually take both — both
   are append-only.
4. **Code conflicts**: prefer behavioural correctness over syntactic
   convenience; rerun the relevant self-test if the conflict is in a
   covered path.

Never use `git checkout --theirs` / `--ours` blanket-style across
multiple files; review each.

## Parallel Sessions

DuetOS may be worked on by several Claude Code sessions at once. File
ownership is coordinated through the tracked coordinator `PARALLEL_WORK.md`
at the repo root plus three helper scripts under `tools/parallel/`. Do
**not** hand-edit `PARALLEL_WORK.md` — the scripts own it. The full
protocol lives in [`CLAUDE_PARALLEL.md`](../../CLAUDE_PARALLEL.md).

```bash
tools/parallel/status.sh                          # active/completed sessions + conflicts
tools/parallel/claim.sh <sub> "<files>" "<desc>"  # claim a subsystem before editing
tools/parallel/release.sh <sub>                   # push the session branch when done
tools/parallel/release.sh <sub> --merge           # ...and merge to main (explicit opt-in)
```

- **`claim.sh`** rebases on `origin/main`, registers this session as
  owning the named subsystem + file globs, warns on already-claimed
  files, and keeps you on your `claude/*` session branch. Session
  identity defaults to host-PID; override with `CLAUDE_SESSION_ID`.
- **`status.sh`** prints each session block and flags the real conflict:
  two live (🟢) claims owning the same path. Completed (✅) claims have
  released their files and are excluded.
- **`release.sh`** flips the subsystem marker 🟢 → ✅, stamps completion,
  and pushes the session branch with `--force-with-lease`. `--merge` is
  the explicit opt-in DuetOS requires before touching `main` — only with
  CI green and no in-flight dependency on another session.

Run `status.sh` and claim your subsystem before editing whenever
concurrent sessions are possible.

## Repository Tooling

Other helper directories under `tools/` worth knowing about:

- **`tools/linux-compat/`** — Linux ABI generators: `gen-linux-syscall-table.py`
  (from `linux-syscalls-x86_64.csv`) and `check-syscall-ownership.py`.
- **`tools/win32-compat/`** — Win32/NT ABI generators: `gen-nt-shim.py`
  (from `nt-syscalls-x64.csv`).
- **`tools/security/`** — host-side security drivers (`run_pentest_gui.py`,
  `attack_from_gui.py`); see [Attack Simulation](../security/Attack-Simulation.md).
- **`tools/cleanroom/`** — cleanroom-trace decoders (`decode_hash.py`,
  `decode_syscall.py`) and the `run-trace-survey.sh` survey harness.
- **`tools/release/`** — release bookkeeping (`update-lifetime-downloads.py`).

Each tool dir keeps a header comment / `README.md` describing usage; the
shared discipline is in `CLAUDE.md` ("Reusable Tooling — Save It").

## Related Pages

- [Build System](Build-System.md)
- [Coding Standards](Coding-Standards.md)
- [Anti-Bloat Guidelines](Anti-Bloat-Guidelines.md)
- [QEMU Smoke Tests](QEMU-Smoke.md)
- [Contributing](../advanced/Contributing.md)
