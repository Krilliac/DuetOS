# AI-Assisted Development — Bloat Pattern and Countermeasures

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

AI-assisted development has a structural, unavoidable tendency toward bloat. This is not a bug in any single session — it is a systemic property. Understanding why it happens is required to prevent it.

In an OS codebase the stakes are higher than in application code: a "just-in-case" abstraction in a kernel memory allocator, syscall table, or driver ABI can outlast the person who added it by a decade. Removing it later usually means breaking binary compatibility.

## Context

Observed repeatedly across AI-assisted projects (including the SparkEngine repo that seeded this one). The pattern reproduces regardless of project domain; what changes is only where the bloat accretes. In DuetOS the predictable hot spots are:

- Kernel utility headers (list helpers, string helpers, "maybe we'll need this" containers)
- Driver skeletons with lifecycle methods that are never called
- Syscall dispatch tables with numbered stubs that do nothing
- Win32 subsystem DLL reimplementations with surface that nothing in the system actually calls yet

## Details

### Why AI Creates Bloat

**1. No pain from complexity**
A human developer feels the cost of a 261 KB file when they spend 3 hours debugging it. AI never feels that. Each session starts fresh; the accumulated mess is invisible until it's catastrophic.

**2. Addition feels productive; removal does not**
Every new feature, method, or class looks like forward progress. Deleting code looks like going backwards. AI has no natural counter-pressure.

**3. "What if we need this later?" thinking**
AI defaults to comprehensive solutions. A simple physical page allocator becomes a full NUMA-aware, per-zone, watermarked, compaction-capable allocator — because "it might be needed."

**4. Systems built but not integrated**
AI builds things. AI may not always wire them in. A driver with a fully implemented `probe()` / `attach()` / `detach()` lifecycle is dead code if nothing on the PCI bus enumerator matches its vendor/device ID pair.

**5. Parallel duplication**
Two systems doing overlapping things get built independently and neither gets removed. Two memory allocators, two string types, two list implementations — all "useful in different situations" and all increasing the surface area future sessions have to reason about.

**6. Each session sees a small change**
No single session adds an outrageous amount. 50 lines here, a new method there. After 20 sessions: 261 KB files and systems nobody can understand.

### OS-Specific Failure Modes

| Location | Bloat Type | Why it's dangerous here |
|----------|-----------|------------------------|
| Syscall table | Reserved / stub entries | Syscall numbers are ABI; stubs printed as "unknown syscall" still consume a number |
| Driver skeleton files | Half-wired `probe()`/`attach()` | Future refactor may wire them up without realizing the driver was never finished |
| Win32 DLL exports | Methods returning `STATUS_NOT_IMPLEMENTED` | Callers think they can call them; hide real missing-functionality bugs |
| Kernel headers | "Utility" classes with no callers | Compile time cost across every TU that includes the umbrella header |
| HAL abstractions | Interfaces with one implementation | Extra indirection with no payoff; makes call paths harder to follow |

### The Compounding Effect

Bloat compounds. A bloated file is harder to read, so the next session adds another helper function instead of understanding the existing code. That makes it more bloated. After N sessions, the file is incomprehensible and nobody touches it — it just accumulates more wrappers.

## Solution / Summary

### Per-Session Rules (enforced in CLAUDE.md)

1. **Size thresholds**: `.cpp`/`.c`/`.rs` ≈500 lines, `.h`/`.hpp` ≈300 lines. Not hard limits — prompts to pause.
2. **Removal mandate**: every PR that adds code should justify the addition; aim for net-neutral or net-negative line counts on refactors.
3. **Wire-in requirement**: if a driver has `probe()`, it must be registered; if a subsystem has `init()`, it must be on an initcall list; if a syscall has a handler, it must be in the dispatch table.
4. **No orphaned code**: dead code is deleted immediately, not commented out.
5. **Bloat check at session start**: `find kernel drivers subsystems userland -type f \( -name '*.cpp' -o -name '*.c' -o -name '*.rs' \) | xargs wc -l | sort -rn | head -15`.
6. **No reserved/stub ABI**: don't add a syscall number or DLL export until there's a real implementation behind it.

### When You Notice Bloat Mid-Task

Do not defer. If the file you're editing is over the limit:
1. Trim it first — delete dead code, consolidate duplicate methods, remove unused members.
2. Then make your actual change.
3. The PR should show a net negative line count or small positive.

### What "Minimal" Means Here

- **Wrong**: add a `DeviceClass` base interface with 12 virtual methods "for future driver classes."
- **Right**: add exactly the driver you need today; factor common code out only when there are ≥2 real drivers.

If the fix is more than 10 lines, ask: "What am I adding that I don't need?"

## Notes

- This problem is not fixable with AI alone — human review focused on *removal* is the real safeguard.
- The CLAUDE.md Anti-Bloat Rules section is the living enforcement mechanism; update it when new patterns are found.
- "Looks good, simplify it" is a valid and important review comment — it should be used often.
- **See also:** [workflow-patterns.md](workflow-patterns.md) for the session-start bloat check; [clang-format.md](clang-format.md) for the full-tree format pattern.
