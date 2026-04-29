# Coding Standards

> **Audience:** All contributors
>
> **Execution context:** N/A
>
> **Maturity:** Stable

## Overview

This page restates the coding standards from `CLAUDE.md` so
contributors can find them without reading the agent context file.

## Languages

- **C++23** for kernel and most subsystems. Features we use:
  `constexpr`, `enum class`, `std::expected`-style `Result<T,E>`,
  concepts, `if consteval`. **No RTTI, no exceptions** in kernel code
  — results go through `duetos::core::Result<T, E>` (see
  `kernel/util/result.h`). Prefer `return Err{ErrorCode::Foo};` +
  `RESULT_TRY` / `RESULT_TRY_ASSIGN` at call sites over
  `return -1 / false / nullptr` sentinels.
- **Rust** permitted for greenfield subsystems where memory-safety vs.
  C++ lifetime invariants matter (filesystem drivers, USB stack,
  network stack). Subsystems must stand alone — **no Rust-in-the-
  middle of a C++ call chain**.
- **ASM**: NASM (Intel syntax) for x86_64 boot, trap frames, context
  switch. Hand-written assembly stays at the smallest possible
  surface.

## Ownership and Memory

- `std::unique_ptr` / `UniquePtr` owning, raw pointers non-owning.
- In kernel, use the project's own smart-pointer primitives —
  `std::` is user-land only.
- **No naked `new`/`delete`** in portable code. Kernel allocations
  go through the slab/page allocators explicitly, never through a
  global `operator new`.
- **No global mutable state** outside the kernel's explicit per-CPU
  areas. If something looks like a singleton, it's probably a
  per-CPU or per-process structure.

## Style

- **Const-correctness**: `const` on all non-mutating methods and
  parameters. `constexpr` wherever it works.
- **Naming**: PascalCase classes/methods, camelCase locals, `m_`
  prefix members, `UPPER_SNAKE` macros and kernel constants, `k_`
  prefix for kernel-internal globals.
- **Headers**: `#pragma once`, forward-declare where possible, no
  transitive include bloat.
- **Format**: Allman braces, 4-space indent, 120-col limit (see
  `.clang-format`). LF line endings everywhere.

## Warnings

**Zero warnings.**

- `-Wall -Wextra -Wpedantic -Werror` on GCC/Clang
- `/W4 /WX` on MSVC

## Stub Markers

- `// STUB:` — handler returns a constant / does nothing /
  returns `-ENOSYS` / returns the wrong target. Real callers WILL
  behave incorrectly. Marker stays until a real implementation
  lands.
- `// GAP: <missing> -- <revisit>` — handler is correct for the v0
  happy path but a documented edge case is unimplemented.

**Do not** sprinkle STUB/GAP markers on code that does its job —
the convention exists to bound the gap inventory. If removing the
marker wouldn't change a maintainer's belief about what works,
don't write it.

The audit baseline is:

```bash
git grep -nE "// (STUB|GAP):"
```

`docs/sync-wiki.sh sync` counts these into the `Home.md` statistics
block.

## Assembly Files Are Not Formatted by clang-format

`.S` files are NOT formatted by `clang-format`. Never pass a `.S`
file to `clang-format -i` — it will parse it as C++ and mangle it.
Assembly stays hand-formatted.

## Kernel vs. Userland

Be **explicit** about which side a piece of code runs on. Kernel
has:

- No `malloc` (use the slab/page allocators)
- No `printf` (use `klog` / `SerialWrite`)
- No exceptions (use `Result<T, E>`)
- No `std::` (use the kernel's own primitives)

## Related Pages

- [Anti-Bloat Guidelines](Anti-Bloat-Guidelines.md)
- [Git Workflow](Git-Workflow.md)
- [Build System](Build-System.md)
- [Contributing](../advanced/Contributing.md)
