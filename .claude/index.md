# Persistence Context — Index

_Read this at every session start (after git sync). Each row links to a detailed knowledge file._

## Knowledge Index

| Topic | File | Type | Status | Last Updated |
|-------|------|------|--------|--------------|
| AI bloat pattern and countermeasures | [knowledge/ai-bloat-pattern.md](knowledge/ai-bloat-pattern.md) | Observation | Active | 2026-04-20 |
| clang-format — CI-matching invocation | [knowledge/clang-format.md](knowledge/clang-format.md) | Pattern | Active | 2026-04-20 |
| Git rebase conflict resolution | [knowledge/git-rebase-conflicts.md](knowledge/git-rebase-conflicts.md) | Pattern | Active | 2026-04-20 |
| GitHub API / PR checks diagnosis | [knowledge/github-api-pr-checks.md](knowledge/github-api-pr-checks.md) | Pattern | Active | 2026-04-20 |
| Build and CI workflow speedups | [knowledge/build-optimizations.md](knowledge/build-optimizations.md) | Optimization | Active | 2026-04-20 |
| Effective dev workflows | [knowledge/workflow-patterns.md](knowledge/workflow-patterns.md) | Pattern | Active | 2026-04-20 |
| Win32/NT subsystem architecture | [knowledge/win32-subsystem-design.md](knowledge/win32-subsystem-design.md) | Decision | Active | 2026-04-20 |
| Hardware target matrix (CPU/GPU/IO tiers) | [knowledge/hardware-target-matrix.md](knowledge/hardware-target-matrix.md) | Decision | Active | 2026-04-20 |

## Quick Reference

### Current Project State (2026-04-20)

- **Repository**: greenfield. README + `CLAUDE.md` + `.claude/` + dotfiles only. No kernel code yet.
- **Default branch**: `main`.
- **Active dev branch**: `claude/port-sparkengine-components-f38iH` (Claude-driven bootstrapping).
- **Platforms**: x86_64 first (UEFI). ARM64 planned, not started.
- **Toolchain** (planned): Clang 18+ / GCC 13+, CMake 3.25+, NASM 2.16+, lld, Rust nightly if/when used.
- **Build system**: not yet written. Do not invent presets.
- **CI**: not yet wired. When it lands, mirror locally with the commands in `CLAUDE.md` → "Pre-commit checks".

### Project Pillars (one-liners)

- PE executables run as a **native ABI**, not through an emulator shell.
- Kernel is a **hybrid** (microkernel IPC shape, monolithic hot paths).
- **Direct GPU drivers** for Intel / AMD / NVIDIA; Vulkan is the primary user-mode API.
- **Capability-based IPC**; no setuid.
- **W^X, ASLR, SMEP/SMAP, KASLR, CFI** enforced from day one.

### Before Writing Code

1. Check file size — if over 500 lines (`.cpp`/`.c`/`.rs`) or 300 lines (`.h`/`.hpp`), consider splitting.
2. Search for existing implementations before adding new ones — especially low-level primitives (spinlocks, allocators, list helpers).
3. Be explicit about kernel vs. user space. Kernel has no `malloc`, no `printf`, no exceptions.
4. Run `clang-format -i` on modified files before committing.
5. If adding a syscall number, remember: **once published, it's ABI forever.**

### CI Quick Reference

- Once CI is online, treat `check-format` as the canonical formatter check. Mirror it locally using the full command in `.claude/knowledge/clang-format.md`.
- Use GitHub MCP tools in this environment (not `gh`) for PR polling. See `.claude/knowledge/github-api-pr-checks.md`.
- Pre-push order: format → configure → build → tests → QEMU smoke.

---

_To add a new entry: create a file in `knowledge/`, add a row to the table above, then commit both. Delete completed single-shot session logs — the code is in the repo and the history is in git._
