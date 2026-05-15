# Codebase Analysis

> **Audience:** All contributors
>
> **Execution context:** Host (Linux dev machine)
>
> **Maturity:** Static gates wired; dynamic phase opt-in

## Overview

`tools/dev/analyze.sh` is the single entry point for static and
dynamic codebase analysis. It runs **our own** analyzer (DuetOS
architecture invariants that no off-the-shelf tool knows about)
alongside the **external** analyzers (cppcheck, clang-tidy, clippy),
and an opt-in dynamic sanitiser-boot phase.

```bash
tools/dev/analyze.sh            # own + cppcheck + clang-tidy(advisory) + clippy
tools/dev/analyze.sh --dynamic  # also: ubsan + kasan QEMU boot smoke
tools/dev/analyze.sh --help     # phase toggles
```

## Phases

| Phase | Tool | Gating? | Notes |
|-------|------|---------|-------|
| `own` | `tools/dev/invariant-check.sh` | **yes** | DuetOS architecture rules |
| `cppcheck` | cppcheck | **yes** (error severity) | whole-tree; suppressions for verified FPs |
| `tidy` | clang-tidy | no (advisory) | sampled; mirrors CI's advisory job |
| `clippy` | cargo clippy | **yes** | `--workspace -D warnings`, mirrors CI |
| `dynamic` | ubsan + kasan QEMU boot | **yes** when run | opt-in (`--dynamic`); needs qemu |

The gating split mirrors `.github/workflows/build.yml`: clippy and the
sanitiser boots are hard gates; clang-tidy on a freestanding kernel is
advisory because a full pass is dominated by false positives. Missing
optional tools (cppcheck, clang-tidy, qemu) downgrade their phase to a
skip with an `apt` hint — they never fake a pass and never hard-fail
on absence.

## Our own analyzer — `invariant-check.sh`

External analyzers enforce *language* rules; `invariant-check.sh`
enforces *DuetOS architecture* rules from `CLAUDE.md` that they
structurally cannot see. A check earns a place only if it is
high-signal and near-zero false-positive on the current tree, so a
non-zero exit is always a real regression.

Gating invariants:

1. **Userland is freestanding** — no `userland/**` TU includes a
   kernel header (subsystem-isolation rule 3).
2. **No `std::` in kernel code** — `std::` is userland-only.

Informational (never gating): the STUB/GAP marker inventory and the
anti-bloat threshold report.

Deliberately *excluded* as too noisy to gate: a grep for naked
`new`/`delete` (matches the words in strings/identifiers) and a
cross-subsystem `#include` grep (flags documented, intentional shared
kernel-owned primitives such as the single pipe pool and the single
directory-enumeration helper, which both ABI front-ends correctly call
per the "one source of truth per resource" rule). Language-level
smells are clang-tidy/cppcheck's job.

## cppcheck suppressions

`tools/dev/cppcheck-suppressions.txt` holds **only** findings traced
to a confirmed cppcheck analysis blind spot. Two account for every
current entry:

1. **`comparePointers` on linker-script section symbols** —
   subtracting/comparing `_text_start`/`_text_end`,
   `__init_array_*`, `ap_trampoline_*`, `__duetos_hotpatch_pairs_*`.
   These are distinct objects to the C++ abstract machine but the
   linker script defines them to bracket one contiguous region; the
   arithmetic is the correct way to size a section.
2. **`arrayIndexOutOfBounds` on NUL-guarded bounded string copies** —
   `for (i=0; s[i] != '\0' && i < CAP; ++i)` reads `s[i]` only while
   non-NUL. cppcheck's ValueFlow ignores the guard, assumes `i`
   reaches `CAP`, then matches a short string-literal caller and
   reports an unreachable overrun.

Entries are line-pinned (`id:file:line`), not file-wide: if a line
drifts the suppression stops matching and the known FP re-appears
loudly — it can never silently mask a *new* real bug elsewhere in the
same file. When a new cppcheck `error` appears: **fix the bug**; add a
suppression *only* after proving it is one of the blind spots above,
with the reason in the file.

## Relationship to `check-local.sh` and CI

`tools/dev/check-local.sh --analyze` runs this harness as part of the
local preflight. The gating phases are the same signals CI enforces;
running `analyze.sh` locally before pushing keeps local and CI in
lockstep and front-loads the cppcheck/own-invariant signals that CI's
advisory clang-tidy job does not gate on.
