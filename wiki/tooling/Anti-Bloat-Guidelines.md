# Anti-Bloat Guidelines

> **Audience:** All contributors
>
> **Execution context:** N/A
>
> **Maturity:** Stable doctrine

## Overview

AI-assisted development has a structural bias toward complexity:
adding features "just in case," creating helpers for single uses,
over-engineering simple problems, building systems without wiring
them in. **In an OS codebase — where the wrong abstraction lives
forever in the kernel ABI — this bias is more dangerous than in
application code.**

The goal is **sanity, not sacrifice** — keep code clean without
stripping legitimate verbosity or readability.

## Sensible Thresholds (Not Hard Limits)

These are **guidelines for when to pause and think**, not absolute
rules. A clean 450-line `.cpp` is fine; a cryptic 200-line `.cpp`
is not.

| Thing | Threshold | What to do |
|-------|-----------|------------|
| `.cpp` / `.c` / `.rs` file size | ~500 lines | Split if doing multiple jobs; leave if one coherent unit |
| `.h` / `.hpp` file size | ~300 lines | Split if unrelated types; data-heavy headers are fine |
| Public methods per class | ~15 | Ask: "Does each method earn its place?" |
| Function length | ~60 lines | Split if nested branching; clear linear flow is fine |
| Syscall handlers per file | 1 subsystem per file | Consolidate before adding more |
| Parallel subsystems doing the same thing | 0 | Remove the duplicate |

## The Readability Principle

**Never sacrifice readability to hit a line count.** Keep:

- Comments that explain "why"
- Descriptive variable names (`pageTableEntryMask` > `ptm`)
- Vertical whitespace between logical sections
- Braces for non-trivial loop bodies
- One statement per line

The question is always: **"Does this make sense to someone reading
it for the first time, at 2am, during a triple-fault?"**

## Before Writing Code — Checklist

1. **Does this already exist?** Search before writing — especially
   for low-level primitives (spinlocks, allocators, list helpers).
2. **Will this be called?** If you can't name the caller, don't
   write it.
3. **Can existing code do this with a small change?** Prefer
   editing over adding.
4. **Is this a one-time use?** Inline it — no helper function, no
   new class.
5. **Am I future-proofing?** Stop. Write only what is needed today.
6. **Adding a new subsystem?** Ask if an existing one can be
   extended instead.
7. **Adding a new syscall?** Syscall numbers are an ABI. Once
   published, they are forever. Be sure.
8. **Is the code dead?** Delete it. Don't comment it out — git
   history exists.
9. **Is a system built but not wired in?** Either wire it in or
   delete it.
10. **Is this running in kernel or user space?** Be explicit. Kernel
    code has no `malloc`, no `printf`, no exceptions unless the
    project explicitly supports them.

## Wiring Things In — Functionality Is Not Optional

A system that exists but is never initialized, called, or connected
is **worse than not existing**. In kernel space, dead code is not
merely wasteful — it rots silently until the day a refactor
accidentally re-enables it and triple-faults the box.

- **Every driver must be probed.** If `probe()` exists, the bus
  enumerator must call it for matching devices.
- **Every syscall handler must be in the dispatch table.** A
  handler that compiles but isn't dispatched is dead code.
- **Every initcall must run.** If a subsystem has an `init()`, it
  must be on a known init list with a stated ordering.
- **Every sink must have a source.** If a system receives data,
  something must be sending it.

If you discover a subsystem that is built but not wired in:
**either wire it in immediately, or delete it.**

## The AI Bloat Pattern

The persistent observation log
(`.claude/knowledge/ai-bloat-pattern.md`) tracks the specific
failure modes that recur when an LLM is the author. They include:

- Adding a "future-proof" abstraction the next slice will need to
  delete
- Building parallel subsystems instead of extending the one that
  exists
- Wrapping a one-line operation in a helper function with a
  five-line docstring
- Adding error handling for cases the function's preconditions
  rule out
- Inventing a feature flag for a binary decision the user already
  made

Recognise the pattern; refuse the urge.

## Related Pages

- [Coding Standards](Coding-Standards.md)
- [Contributing](../advanced/Contributing.md)
