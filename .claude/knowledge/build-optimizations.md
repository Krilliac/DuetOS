# Build and CI Workflow Optimizations

**Last updated:** 2026-04-20
**Type:** Optimization
**Status:** Active

## Description

Concrete time and effort savers for build, CI diagnosis, and git workflows. These are faster or more reliable alternatives to the obvious first approach. These are not correctness fixes — the default approaches work — they are efficiency improvements.

## Context

Applies to any session involving building, testing, CI diagnosis, or git operations in DuetOS. Most apply once the build system is in place; the git ones apply today.

---

## Optimization: Always use `--parallel $(nproc)` for CMake builds

### Approach

Always pass `--parallel $(nproc)` to `cmake --build` to exploit all available CPU cores:

```bash
cmake --build build --parallel $(nproc)
```

Without this flag, CMake builds single-threaded by default on some configurations, which is dramatically slower on multi-core hosts. Kernel + userland + multiple GPU drivers compounds the difference — a single-threaded build can be >10× slower on a modern workstation.

### Notes

- `$(nproc)` is Linux/bash-specific. On macOS use `$(sysctl -n hw.logicalcpu)`.
- All CI jobs (once defined) should use `--parallel $(nproc)` — this makes local builds match CI speed.
- Kernel links can still be a bottleneck; `lld` is preferred over `ld.bfd`/`gold` for this reason.

---

## Optimization: Check branch delta before rebasing

### Approach

Before running `git rebase origin/main`, check how many commits you're behind. This tells you whether to expect conflicts and how many:

```bash
git log --oneline HEAD..origin/main | wc -l
```

| Output | Action |
|--------|--------|
| `0` | Branch is up to date — skip rebase entirely |
| `1–3` | Straightforward rebase, unlikely to conflict |
| `4–10` | Moderate delta — read commit messages before rebasing |
| `10+` | Large delta — review commits first with `git log --oneline HEAD..origin/main` |

### Notes

- **See also:** [git-rebase-conflicts.md](git-rebase-conflicts.md) for conflict resolution strategies.
- Checking first prevents surprises mid-rebase on large divergences.

---

## Optimization: Pull only the failed job's log, not the whole run

### Approach

When a CI run fails, skip reading the full log — at a typical kernel matrix size this will be tens of MB. Use whatever mechanism the GitHub MCP tools expose for per-check-run logs (equivalent of `gh run view --log-failed`), and read **only** the failed job's output.

### Notes

- Full logs for a full matrix run routinely hit 10–50 MB. Most of it is sysroot messages and clean passes.
- **See also:** [github-api-pr-checks.md](github-api-pr-checks.md) for the full PR check diagnosis workflow.

---

## Optimization: CMake dry-run to verify preset flags

### Approach

Once presets exist, use the `-N` flag to do a CMake dry-run that prints all resolved options without actually configuring:

```bash
cmake --preset x86_64-release -N
```

Useful for verifying which CMake toggles (`ENABLE_KASAN`, `ENABLE_GPU_AMD`, `WIN32_SUBSYSTEM`, etc.) are set by a preset before committing to a full configure.

### Notes

- Much faster than a full configure when you just need to check a flag.
- Kernel builds often flip many toggles; a dry-run catches misnamed options without burning a full reconfigure cycle.

---

## Optimization: Prefer `ccache` for iterative kernel rebuilds

### Approach

Enable `ccache` in the CMake configure step so that repeated debug rebuilds of the kernel + driver tree hit cache:

```bash
cmake --preset x86_64-debug \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
```

This compounds with `--parallel $(nproc)` — after the first full build, iterative changes rebuild only what's actually different, not a whole translation unit.

### Notes

- CI runners should share a ccache directory across jobs once we have runners under our control.
- Be careful with cross-compilation toolchains (MinGW, bare-metal) — give each its own `CCACHE_DIR` so cache entries don't cross-contaminate.

---

## Optimization: Keep a hot QEMU launcher for boot-path iteration

### Approach

Once `tools/qemu/run.sh` exists, wire it to launch QEMU with `-snapshot`, a fixed RAM size, and a serial console piped to stdout. Iterating on the boot path becomes "edit → build → run.sh → observe serial" without rebuilding the disk image each time.

### Notes

- `--snapshot` avoids corrupting the image on a crash; you can kill QEMU hard and the disk is untouched.
- Prefer `-serial mon:stdio` over `-nographic` during bring-up so Ctrl-C still interrupts QEMU rather than reaching the guest.
- For triple-fault diagnosis, add `-d int,cpu_reset -D qemu.log` — it's the single most useful debugging knob early on.
