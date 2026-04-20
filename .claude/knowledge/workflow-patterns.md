# Effective CustomOS Development Workflows

**Last updated:** 2026-04-20
**Type:** Pattern
**Status:** Active

## Description

Recurring workflows that reduce time spent on overhead and increase the reliability of outputs. Apply them proactively rather than waiting until something goes wrong.

## Context

Applies to all CustomOS development sessions. Most patterns correspond to gaps where the "obvious" approach is slower or less reliable than the pattern described here.

---

## Pattern: Codebase Exploration — Parallel Explore agents

### Approach

When a task touches multiple areas of the codebase (e.g., adding a feature that spans `kernel/mm/` + `kernel/syscall/` + `subsystems/win32/`), launch 2–3 Explore agents **in parallel** rather than sequentially. Each agent gets a specific search focus.

```
Agent 1: "Search for existing implementations of X in kernel/mm/"
Agent 2: "Find all callers of Y in kernel/syscall/"
Agent 3: "Identify patterns for Z in subsystems/win32/ntdll/"
```

Do not use a single Explore agent for a broad multi-area search — it will either miss areas or spend too long on one area.

### When to apply

- Task involves code in 2+ directories
- Scope is uncertain and you need to map the codebase before planning
- Looking for an existing implementation before writing new code (always check first)

### Notes

- Use `subagent_type: Explore` for read-only codebase research
- Use `subagent_type: Plan` when you need architectural design work after exploration
- 3 agents maximum per parallel batch; quality over quantity

---

## Pattern: Pre-push checklist order

### Approach

Run pre-push checks in this specific order — each step catches different error classes and the order minimizes wasted time:

```bash
# 1. Format first (fastest, most common failure)
find kernel drivers subsystems userland \
  \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | xargs clang-format --dry-run --Werror 2>&1

# 2. CMake configure (catches missing headers, broken includes)
cmake --preset x86_64-release 2>&1 | tail -20

# 3. Build (catches compile errors)
cmake --build build --parallel $(nproc) 2>&1 | tail -30

# 4. Tests (catches regressions)
cd build && ctest --output-on-failure && cd ..

# 5. QEMU smoke (catches runtime regressions on the boot path)
tools/qemu/run.sh --headless --timeout 30 build/customos.img
```

Stop at the first failure; fix it before proceeding to the next step.

### Notes

- Step 1 (format) is cheap. Do it even for tiny changes.
- Step 2 (configure) detects include path issues early before a full compile.
- Step 5 (QEMU smoke) matters disproportionately in kernel work: a compile-clean change can still triple-fault on boot.
- **See also:** [clang-format.md](clang-format.md) for the full-tree format command; [build-optimizations.md](build-optimizations.md) for `--parallel $(nproc)`.

---

## Pattern: CMake preset over manual flags

### Approach

Once presets exist, always prefer `cmake --preset x86_64-release` over manually constructing `-B build -DCMAKE_BUILD_TYPE=...` flags.

```bash
# Preferred
cmake --preset x86_64-release

# Only use manual flags when a custom toggle is needed
cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_GPU_AMD=ON \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
```

### Notes

- Presets live in `CMakePresets.json` and are authoritative — they match CI's exact configuration.
- If a preset produces unexpected behavior, check `CMakePresets.json` for the exact flags it sets rather than guessing.
- Delete `build/` if switching between preset and manual configure — the cache will conflict.

---

## Pattern: Removal before addition

### Approach

Before writing any new code in a file, check its size. If it is over the threshold (~500 lines for `.cpp`/`.c`/`.rs`, ~300 for `.h`/`.hpp`), trim it first:

```bash
wc -l kernel/mm/paging.cpp

# If over threshold:
# 1. Find dead methods (no callers outside the file)
# 2. Delete them
# 3. Then make your actual change
```

For any new public method being added:
1. Search for existing methods that do something similar.
2. If one exists, extend it — don't add a new one.
3. If there are now 2 similar methods after your change, remove the older one.

For any new subsystem being added:
1. Search for an existing subsystem that could be extended.
2. If adding, remove something of equivalent complexity.

### When to apply

- Every time you open a file to edit it.
- Before every PR — check net line delta: should be ≤ 0 for refactors, minimal positive for features.
- When a file starts feeling hard to navigate.

### Notes

- Removal is not "going backwards" — it is the primary maintenance activity.
- The goal is a codebase that shrinks toward its essential minimum, not grows toward "comprehensive."
- If a feature isn't used by something running today, delete it.
- **See also:** [ai-bloat-pattern.md](ai-bloat-pattern.md) for why this problem is especially acute in AI-assisted work.

---

## Pattern: Session start checklist order

### Approach

Every session should start in this exact order before doing anything else:

1. `git fetch origin main && git log --oneline HEAD..origin/main | wc -l` — assess how far behind.
2. `git rebase origin/main` — sync with upstream.
3. Resolve any rebase conflicts (see [git-rebase-conflicts.md](git-rebase-conflicts.md)).
4. `cat .claude/index.md` — load persistent context.
5. Read any knowledge files relevant to the current task.
6. **Bloat check** — run before touching anything (once the tree has code):
   ```bash
   find kernel drivers subsystems userland -type f \
     \( -name '*.cpp' -o -name '*.c' -o -name '*.rs' \) | xargs wc -l | sort -rn | head -15
   ```
7. **Then** start reading code or planning.

Skipping step 4–5 means starting each session without accumulated knowledge. Skipping step 6 means walking into a bloated file blind.

### Notes

- If `wc -l` output is 0 in step 1, the branch is up to date — skip the rebase.
- Never start reading or editing code before completing the git sync. Stale code leads to conflicts on push.
- The bloat check takes 2 seconds. Files over threshold should be trimmed before adding to them.
- **See also:** [ai-bloat-pattern.md](ai-bloat-pattern.md) for why this problem exists and how to prevent it.

---

## Pattern: Kernel vs. userland boundary first

### Approach

Before writing any function, state in your head (or in a one-line comment at the top of the file) which address space it runs in:

- **Kernel**: no `malloc`, no `printf`, no exceptions, no `std::` containers (use kernel equivalents). All allocations go through the kernel allocator.
- **User**: standard freestanding libc+ subset, normal allocators, normal panics.
- **Win32 subsystem**: runs in the target process's user-mode context. Shared state goes through an explicit kernel port, never a singleton.

A function that is unclear about its context is a bug waiting to happen — kernel allocators called from user code, or user-mode locks taken from interrupt context, are two of the most common early-OS bug patterns.

### Notes

- If the function needs to be callable from both contexts, split it: a pure-logic core (header-only or `static inline`) plus thin kernel/user wrappers.
- Document the context in the **header**, not the `.cpp`. Callers see headers.
