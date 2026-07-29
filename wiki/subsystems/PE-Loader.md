# PE Loader

> **Audience:** Kernel hackers, PE/Win32 devs, security folks
>
> **Execution context:** Kernel — process context during spawn
>
> **Maturity:** Stage 2 — real-world MSVC PEs load and run

## Overview

The PE loader takes a PE32+ image (validated DOS + NT headers, section
table, data directories) and produces a runnable user process. Stage 2
closed the gaps that prevented real third-party Windows binaries from
loading: forwarder chasing (name-form and ordinal-form), by-ordinal IAT
resolution, binary-search EAT lookup.

## Files

- `kernel/loader/pe_loader.cpp` — main load path
- `kernel/loader/pe_exports.cpp` — `IMAGE_EXPORT_DIRECTORY` parser,
  binary-search export lookup
- `kernel/loader/dll_loader.cpp` — DLL load + per-process DLL table
  (IAT walker + forwarder chase live in this TU and `pe_loader.cpp`)
- `kernel/loader/sxs_dll.cpp` — side-by-side DLL loading (DLLs read off
  a volume rather than embedded in the kernel image)

## Where a DLL Can Come From

Four sources, consulted in this order by `SpawnPeFile` before `PeLoad`
walks the IAT. Every one of them ends up in the SAME `preloaded_dlls`
array, so the import binder has one code path regardless of origin.

| Source | Trust | Gated? | Selection |
|---|---|---|---|
| Preload table (`spawn.cpp`) | kernel image | no — part of the TCB | fixed ~44-entry list |
| ramfs `/lib/*.dll` | kernel image | no — part of the TCB | every `*.dll` in the directory |
| FAT32 `/LIB/*.dll` on volume 0 | operator-curated disk | **yes** | every `*.dll` in the directory |
| The image's OWN directory | guest-writable disk | **yes** | driven by the import table |

The last row is **side-by-side loading** — how essentially all real
software ships. `SpawnPeFile` takes an on-disk origin (volume + path),
derives the directory once, and records it on the `Process`
(`sxs_volume` / `sxs_dir`). Both the load-time import binder and the
runtime `SYS_DLL_LOAD_FROM_PATH` (`LoadLibraryW`) read that one field,
so there is a single search path per process rather than a bind-time
and a run-time answer that can disagree.

Resolution is **import-name driven**, not speculative: only DLLs the
image (or one of its dependencies) actually names are read, so pointing
the loader at a game folder does not drag the folder in. It is also
recursive — a side-by-side DLL's own side-by-side dependencies resolve
— under two hard bounds:

- `kSxsMaxDepth = 4` — the .exe is depth 0.
- `kSxsMaxLoads = 16` per spawn, independent of depth, so a *wide*
  hostile import table is bounded as well as a deep one.

Cycles terminate for free: a name already present in the resolution set
is never read again, and the set is checked before every disk access.

### Security contract

A DLL read off a FAT32 volume is guest-writable and executes inside the
process's address space with the process's authority — the same
exposure a disk-sourced `.exe` has. Both disk sources therefore pass
`security::Gate` with `ImageKind::WindowsPE`, exactly as `PeLoad` gates
the `.exe`. Blobs compiled into the kernel image and files under the
trusted ramfs root are part of the TCB and are deliberately not
re-gated (44 guard scans per spawn would be pure cost).

This is observable. Booting `BattleBit.exe` with its real
`UnityPlayer.dll` staged beside it, with the autonomic engine having
escalated the guard to Enforce, produces:

```
[guard] WARN kind=pe name="/UNITYPLA.DLL" findings=0x1
[guard]   - PE_SUSPICIOUS: 2+ injection-family APIs
[guard] prompt timeout: default-deny
[sxs] security guard blocked path="/UNITYPLA.DLL"
```

Everything else fails closed too: the advertised file size is bounded
before any allocation, a short read is refused rather than handed to the
PE parser, the never-freed byte cache has both a slot count
(`kCacheSlots = 16`) and a total budget (`kSxsCacheBudgetBytes = 40 MiB`),
and a path join that would truncate declines the load instead.

API-set contract names (`api-ms-win-*` / `ext-ms-win-*`) are never taken
to disk. No filesystem, here or on Windows, has a file by those names.

### Short-name fallback

`tools/qemu/make-gpt-image.py` writes 8.3 short names only, so an import
naming `UnityPlayer.dll` will not match a directory entry literally. The
resolver retries against the truncated uppercase form
(`UNITYPLA.DLL`). **GAP**: no `~1` tilde disambiguation — that needs
on-demand directory enumeration to count collisions, which the FAT32
layer does not expose yet.

## Load Sequence

1. **Validate**: DOS magic `MZ`, e_lfanew bounds, NT magic `PE\0\0`,
   PE32+ optional-header size, machine = `0x8664`.
2. **`PeReport`**: walks every data directory, prints section table,
   lists every imported DLL and function, counts base-relocation
   blocks, counts TLS callbacks. Run for *every* spawn including ones
   that will be rejected — this is the diagnostic that drove the
   loader's evolution.
3. **Address space**: allocate `mm::AddressSpace`, mirror kernel half.
4. **Preload set**: register every userland DLL into the per-process
   DLL table (`Process::dll_images[]`). All 44 production DLLs in
   `userland/libs/` are preloaded on real hardware (plus 2 customdll
   test fixtures, for 46 total entries in `preload_set[]`). Under
   `arch::IsEmulator()` the 9 entries marked `essential=false`
   (7 production DLLs + 2 fixtures) are skipped to keep CI runs
   short; the 37 essential production DLLs always preload.
   ~1100 exports total.
   Per-DLL status lives in
   [`Win32-Surface-Status`](../reference/Win32-Surface-Status.md).
5. **Map sections**: each PE section mapped at `ImageBase + VA` with
   flags from `Characteristics` (`MEM_EXECUTE`, `MEM_WRITE`,
   `MEM_READ`). W^X is enforced — a section requesting both write +
   execute is rejected at map time.
6. **Apply relocations**: DIR64-style base relocations (only `IMAGE_REL_BASED_DIR64`
   is honoured; others are inert in PE32+).
7. **Walk imports**: for each `(dll_name, func_name | ordinal)`:
   - Look up `dll_name` in the per-process DLL table.
   - Resolve the export by name (binary search) or by ordinal
     (direct EAT index).
   - **If the export is a forwarder** (`Dll.Func` or `Dll.#N`),
     recurse through the per-process DLL table. Bounded depth.
   - Patch the IAT slot with the absolute VA of the resolved entry.
8. **Bootstrap heap + main thread**. The main thread's stack is a
   demand-grown reservation sized from the Optional Header — see
   [Ring-3 Stacks](#ring-3-stacks).
9. **Entry**: schedule first user task at
   `ImageBase + AddressOfEntryPoint`.

## Forwarder Chasing

A forwarder export looks like `kernel32.GetProcAddress` or
`kernelbase.#0042`. The IAT-patch step resolves it recursively against
the preloaded set. Both name-form and ordinal-form are supported.
Bounded depth prevents pathological loops.

This was a stage-2 closer — without it, `kernelbase` (44 forwarders to
`kernel32`) couldn't be mapped.

## By-ordinal IAT Resolution

PE imports can reference an export by ordinal rather than name:
`IMAGE_IMPORT_BY_NAME` vs `IMAGE_ORDINAL_FLAG`. The loader handles
both — by-ordinal lookups index directly into the preloaded EAT.

Stage 2 closer; before this, MSVC binaries that import by ordinal
would fail at the IAT-patch step.

## EAT Binary Search

`PeExportLookupName` is binary-search (the EAT's name-pointer table is
sorted lexicographically). For DLLs with hundreds of exports
(`kernel32` has 155, `ntdll` has 114) this matters at spawn time.

## Stub Markers

Anywhere the loader takes a "good enough for v0" shortcut is marked
with `// STUB:` or `// GAP:`. See
[Logging and Tracing](../kernel/Logging-And-Tracing.md) for the
convention.

## Naming an Unresolved Import at Call Time

An import the loader cannot resolve is bound to the shared miss-logger
thunk in the Win32 stubs page: called as a function it returns 0, and
emits one line naming what was called and from where.

```
[win32-miss] fn="UnityMain" slot=0x140edb210 called-from=0x140ed11f2 in-module=0x140ed0000
```

The thunk itself does nothing but pass its own return address to
`SYS_WIN32_MISS_LOG`. **The decode from that return address back to an
IAT slot lives in the kernel**, not in the stub page's hand-assembled
bytes, so it can read the call site through `mm::CopyFromUser`, validate
each step, and report a failure instead of guessing. Recognised shapes:

| Call site (ends at return address) | IAT slot |
|---|---|
| `[48] FF 15 disp32` — `call qword [rip+disp32]` | `ret + disp32` |
| `E8 rel32` — `call rel32` into a jump thunk | decode the thunk (below) |

| Import thunk | IAT slot |
|---|---|
| `48 FF 25 rel32` (7 bytes — what real MSVC output uses) | `thunk + 7 + rel32` |
| `FF 25 rel32` (6 bytes) | `thunk + 6 + rel32` |

A decoded slot must be 8-byte aligned or it is discarded — an
unaligned result is not an IAT slot whatever the opcodes said.

When no shape matches, the line carries `undecoded="<reason>"` and
**no** slot address. That is deliberate: some shapes are genuinely
unrecoverable from a return address alone (a tail `jmp` through the
IAT leaves the caller's caller's return address on the stack;
`call rax` leaves no displacement to read). Reporting them as
unrecoverable is worth more than a plausible wrong address — a wrong
one previously sent an investigation to an unrelated subsystem. See
Design-Decisions, "an unresolved-import miss is decoded in the kernel,
and never guessed".

A decoded slot that is absent from the process's staged-miss table is
also called out explicitly rather than collapsing into `<unmapped>`;
the usual cause is a slot belonging to a DLL whose imports were staged
under a different `PeLoad`, or a staging buffer that overflowed
(`Process::kWin32IatMissCap`, 128).

## API-Set Contracts

`api-ms-win-*` and `ext-ms-win-*` names are contracts, not files — no
such DLL exists on Windows either. `kernel/loader/apiset_static.cpp`
rewrites them to the host DLL that really exports the functions, on
both the import-binding path and the runtime `LoadLibrary` path.

A contract that is **not** in the table returns NULL, and says so:

```
[dll-load] api-set contract has no host (returning NULL, as Windows does) name="api-ms-win-appmodel-runtime-l1-1-2"
```

That is the correct answer rather than a shortfall — callers probe
contracts precisely so they can run on Windows builds that predate
them. A contract is added to the table only when we ship a host that
actually exports its functions; see Design-Decisions, "an api-set
contract with no host returns NULL, not a fabricated mapping".

## Ring-3 Stacks

The main thread's ring-3 stack is a **demand-grown reservation**, laid
out and clamped by `core::UserStackPlan`
(`kernel/proc/user_stack.h`) from the image's own Optional Header:

| Field | Source | Clamp |
|-------|--------|-------|
| reservation size | `SizeOfStackReserve` (offset 72; u32 for PE32, u64 for PE32+) | `[64 KiB, 4 MiB]` |
| initial commit | `SizeOfStackCommit` (offset 76 / 80) | `[2, 16]` pages |

The layout grows downward from `core::kUserStackTopVa` (0x7FFE0000,
immediately below `KUSER_SHARED_DATA`):

```
guard_lo        reserve_lo         commit_lo            top
   |                 |                  |                |
   [  guard region ][ reserved, uncommitted ][ committed ]
    4 pages, fatal    grows a page per #PF     mapped at load
```

`PeLoad` commits only `[commit_lo, top)`. Everything below is address
space until the thread touches it. The ring-3 `#PF` path in
`kernel/arch/x86_64/traps.cpp` calls `core::UserStackServiceFault`
BEFORE the `IsolateTask` policy and before Win32 SEH delivery, because
a growable fault is not an error.

**The growth condition is deliberately narrow.** All four must hold:

1. the fault is not-present (a protection fault on a committed stack
   page is a real error);
2. `reserve_lo <= cr2 < commit_lo`;
3. `commit_lo - cr2 <= 4096` — the fault names the page *immediately*
   below the committed edge. A fault that skips uncommitted pages is a
   wild pointer, not a stack probe;
4. `reserve_lo <= rsp <= top` — the faulting thread is the one running
   on this stack.

Anything else falls through to the existing behaviour untouched. The
tempting phrasing of (4) is "the access is below rsp", and it is
**wrong**: only `push`/`call` fault below rsp; a prologue that has
already done `sub rsp, N` writes at `[rsp + k]`, so cr2 is at or above
rsp. Condition (4) as written is also what makes the whole path
lock-free — every other thread runs on the thread-stack arena at
0x68000000, far below `reserve_lo`, so no other thread can ever
satisfy it and the main thread is the sole writer of `commit_lo`.

**The guard region stays fatal.** A fault in `[guard_lo, reserve_lo)`
returns `Guard`, never `Grow`: the kernel emits
`[W] mm/ustack : *** RING-3 STACK OVERFLOW ***`, fires the
`mm.user_stack_guard_hit` probe, and delivers `STATUS_STACK_OVERFLOW`
(0xC00000FD) rather than a generic access violation. As Windows does,
the guard region is committed *once* at that moment so the thread's
`__except` handler has somewhere to run — it is a one-shot, the
overflowing recursion still dies, and a second runaway walks below
`guard_lo` into unmapped space and takes the ordinary task-kill. Four
pages, because a single page ran out inside
`KiUserExceptionDispatcher` and the second fault killed the thread
before the exception could be reported.

Exception delivery can itself be the thing that needs a page:
`Win32DeliverException` writes the `EXCEPTION_RECORD` + `CONTEXT` onto
the faulting thread's own user stack via `mm::CopyToUser`, which
pre-checks accessibility and returns false rather than faulting. It
therefore calls `core::UserStackCommitRange` first.

Proofs: `tests/host/test_user_stack.cpp` (classifier, exhaustive),
`userland/apps/stackgrow_smoke` (live growth past 512 KiB, battery row
`ring3-stackgrow-smoke`), and `userland/apps/stackguard_smoke` (live
guard hit; battery row `ring3-stackguard-smoke`, `expects_verdict =
false` because it dies by design).

## Known Limits / GAPs

- **Only the main thread's stack grows on demand.** Win32
  `CreateThread` stacks still come off the fixed-size thread-stack
  arena (`Process::thread_stack_cursor`, 0x68000000,
  `Process::kV0ThreadStackPages` each) and overflow into the next
  thread's slot with no guard region. The main-thread reservation is
  demand-grown — see [Ring-3 Stacks](#ring-3-stacks) below.
- **Side-by-side DLL bytes are never freed.** `DllImage` borrows its
  `file` pointer and the parsed export table points into that buffer,
  so the bytes must outlive every process that mapped them. The cache
  is bounded rather than reclaimed; a refcounted unload path lands with
  process-teardown DLL unmapping, which does not exist yet.
- **No SEH unwinding by the loader**. SEH tables are mapped (so the
  `__C_specific_handler` finds them) but DuetOS does not unwind on
  exception — exceptions inside a PE produce a process kill.
- **TLS image-level callbacks**: a non-empty `IMAGE_DIRECTORY_ENTRY_TLS`
  callback array causes the PE load to fail with
  `TlsCallbacksUnsupported` (`pe_loader.cpp:1805`). Empty callback
  arrays — common because the MSVC CRT reserves the directory
  unconditionally — are accepted. A future slice will inject a
  per-process x64 thunk that walks the array with
  `(rcx=image_base, rdx=DLL_PROCESS_ATTACH, r8=nullptr)` before
  jumping to the real entry. Per-thread TLS init via the CRT works.
- **No PE delay-load** (`__delayLoadHelper2`). Anything imported by
  delay-load is treated as eager-import.
- **Bound imports**: the `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT` directory
  is silently ignored. Bound imports are an optimisation that
  embeds resolved addresses for a specific DLL build; safe to skip
  because the eager-import walk re-resolves them, but the loader
  does not validate that the bound timestamps still match.
- **Subsystem field**: the optional header `Subsystem` field
  (`IMAGE_SUBSYSTEM_WINDOWS_GUI` / `_CUI` / `_NATIVE`) is not
  inspected. Both GUI and console binaries are loaded identically;
  `user32`/`kernel32` thunks decide their own behaviour. Native
  subsystem PEs (`smss.exe`-class) are out of scope for v0.
- **`IMAGE_DLLCHARACTERISTICS_NX_COMPAT` bit**: not consulted —
  W^X is enforced unconditionally for every PE regardless of the
  bit. This is stricter than Windows; PEs that incorrectly omit
  the bit still get NX. Recorded for the audit trail, not as a
  fix target.
- **CFG (Control Flow Guard)**: `__security_cookie` is seeded
  (`SeedSecurityCookie` at `pe_loader.cpp:773`) but the
  `GuardCFFunctionTable` is not loaded — indirect calls land
  without CFG validation.
- **Resource section**: mapped read-only but not interpreted — the
  resource APIs (`FindResource`, `LoadIcon`, etc.) walk the section
  themselves.
- **PEB / PEB_LDR_DATA**: the loader populates a minimal v0
  scaffolding inside the TEB page (`pe_loader.cpp` step 4b for
  PE32+) — `gs:[0x60]` -> PEB at TEB+0x100, `PEB.Ldr` at
  PEB+0x20 -> PEB_LDR_DATA at TEB+0x200 with `Length=0x58`,
  `Initialized=1`, and three circular-empty
  `LIST_ENTRY` heads. This is what every loader-walking
  helper stamped by MSVC actually reads (the Unity launcher's
  `mov gs:0x60, %rax; mov 0x20(%rax), %rcx; cmp ebx, 0x8(%rcx)`
  pattern faulted at cr2=0x20 / 0x08 before this landed).
  Real `ImageBaseAddress`, `ProcessParameters`, and the loaded-
  module list itself are NOT populated — anything that iterates
  the list immediately wraps back to the head, the documented
  "no DLLs loaded" state. Adding a non-empty module list is a
  follow-on when a PE that needs `GetModuleHandle` walks for
  itself surfaces.

See [History](../getting-started/History.md) Phases 4-6 for the loader's
evolution.

## Related Pages

- [Win32 PE Subsystem](Win32-PE-Subsystem.md)
- [Win32 DLLs](Win32-DLLs.md)
- [Memory Management](../kernel/Memory-Management.md) — `AddressSpace`
- [Process Model](../kernel/Process-Model.md)
- [W^X / NX Enforcement](../security/WX-Enforcement.md)
