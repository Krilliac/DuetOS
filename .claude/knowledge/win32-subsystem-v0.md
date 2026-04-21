# Win32 subsystem v0 — import resolution + 7 stub batches

**Type:** Observation · **Status:** Active · **Last updated:** 2026-04-21

## Context

The v0 PE loader (`pe-subsystem-v0.md`) could parse any real
Windows PE but only **execute** freestanding images with no
imports. This entry documents the Win32 subsystem on top of
it: a kernel-hosted per-process "stubs page" that maps each
imported `{dll, func}` to a handful of machine-code thunks
translating the Windows x64 ABI into CustomOS native
syscalls.

As of 2026-04-21, **7 batches** of stubs have landed:

| Batch | DLLs | Functions | Notes |
|---|---|---|---|
| 0 (v0) | kernel32 | `ExitProcess` | Scaffolding commit |
| 1 | kernel32 | `GetStdHandle`, `WriteFile`, `WriteConsoleA` | Console I/O |
| 2 | kernel32 | `GetCurrentProcess(Id)`, `GetCurrentThread(Id)`, `TerminateProcess` | + new `SYS_GETPROCID` |
| 3 | kernel32 | `GetLastError`, `SetLastError` | + `SYS_GETLASTERROR`, `SYS_SETLASTERROR`, Process slot |
| 4 | kernel32 | `InitializeCriticalSection`(`Ex`/`AndSpinCount`), `Enter`/`Leave`/`DeleteCriticalSection` | v0 no-ops; fine for single-threaded processes |
| 5 | vcruntime140 | `memset`, `memcpy`, `memmove` | + SSE enablement (CR0/CR4) + rsp alignment fix |
| 6 | 5 apiset DLLs + ucrtbase | ~17 UCRT startup shims | Most → return-0 or nop |
| 7 | 3 apiset DLLs + ucrtbase + msvcrt | `strcmp`, `strlen`, `wcslen`, `strchr`, `strcpy` | Pure assembly loops |

Total: **~45 Win32 functions resolved across 10 DLL names**.
`hello_winapi.exe` exercises every batch on boot; 14 kernel32
imports, 3 vcruntime140, 10+ UCRT apiset imports, all
resolve, all execute, process exits with the round-tripped
`SetLastError(0xBEEF)` value.

## The mechanism, top to bottom

```
userland/apps/hello_winapi/hello.c     (C source: calls ExitProcess(42))
        │
        ▼  host clang --target=x86_64-pc-windows-msvc
userland/apps/hello_winapi/kernel32.def   llvm-dlltool -> kernel32.lib
        │                                     │
        ▼         ▼
lld-link  ───────────►  hello_winapi.exe  (real x64 PE, 2 KiB, 1 import)
        │
        ▼  tools/embed-blob.py
generated_hello_winapi.h   (constexpr u8 kBinHelloWinapiBytes[])
        │
        ▼  #include in kernel/fs/ramfs.cpp
/bin/hello_winapi.exe      (trusted ramfs node)
        │
        ▼  SpawnPeFile -> PeLoad -> ResolveImports
IAT slot at 0x140002038  is patched to  0x60000000  (stubs page VA)
        │
        ▼  ring-3 task enters at rip=0x140001000
PE code:  mov ecx, 42;  jmpq *IAT_SLOT
        │
        ▼  (trampoline through patched IAT)
stub at 0x60000000:  mov rdi, rcx;  xor eax, eax;  int 0x80;  ud2
        │
        ▼  native SYS_EXIT(42)
[I] sys : exit rc val=0x2a     ← the success signature
```

## What each layer provides

| Layer | File | Role |
|-------|------|------|
| Userland source | `userland/apps/hello_winapi/hello.c` | `__declspec(dllimport) void __stdcall ExitProcess(unsigned int)` + `_start` that calls it. No CRT, no libc. |
| Import stub `.def` | `userland/apps/hello_winapi/kernel32.def` | `LIBRARY kernel32.dll / EXPORTS ExitProcess`. Input to llvm-dlltool. |
| Host build | `tools/build-hello-winapi.sh` | Generates kernel32.lib, compiles hello.c, links, embeds via `embed-blob.py`. |
| Kernel stub page | `kernel/subsystems/win32/stubs.{h,cpp}` | 9 bytes of x86-64 machine code per stub + a `{dll, func, offset}` lookup table. |
| Import resolver | `kernel/core/pe_loader.cpp` `ResolveImports` | Walks Import Directory, looks up each `{dll, func}` in the stubs table, patches the IAT slot. |
| Address-space helper | `kernel/mm/address_space.cpp` `AddressSpaceLookupUserFrame` | Given a user VA, returns the backing physical frame — so the resolver can write an IAT slot via `PhysToVirt(frame) + page_offset` without remapping the user page RW. |

## The ExitProcess stub (9 bytes)

```asm
; On entry (Windows x64 ABI):
;   rcx = uExitCode
; On exit:
;   does not return — process terminates.
48 89 CF     mov rdi, rcx      ; native first arg
31 C0        xor eax, eax      ; syscall # = 0 = SYS_EXIT
CD 80        int 0x80
0F 0B        ud2               ; unreachable — SYS_EXIT is [[noreturn]]
```

Mapped at a fixed user VA `kWin32StubsVa = 0x60000000` in every
Win32-imports process. Chosen to not overlap with typical
ImageBase values (0x400000 / 0x140000000) or the ring-3 stack
(0x7FFFE000). R-X, user-accessible, one page per process.

## Boot-time log (success case)

```
[ring3] pe report name="ring3-hello-winapi"
[pe-report] bytes=0x800 parse_status=ImportsPresent
  image_base=0x140000000 entry_rva=0x1000 image_size=0x3000
  sections (2)
    [.text]  rva=0x1000 vsz=0xc    rsz=0x200 flags=0x60000020
    [.rdata] rva=0x2000 vsz=0x63   rsz=0x200 flags=0x40000040
  imports: rva=0x2000 size=0x28
    needs kernel32.dll:
      ExitProcess
  imports total: dlls=1 functions=1
[as] created pml4_phys=0x3d8000 as=...
[pe-resolve] kernel32.dll!ExitProcess -> 0x60000000
[pe-resolve] total resolved: 0x1
[proc] create pid=0xf name="ring3-hello-winapi" caps=0x6
       code_va=0x140001000 stack_va=0x7fffe000
[ring3] pe spawn name="ring3-hello-winapi" pid=0xf
       entry=0x140001000 image_base=0x140000000 stack_top=0x7ffff000
[sched] created task id=0x17 name="ring3-hello-winapi" ...
[ring3] task pid=0x17 entering ring 3 rip=0x140001000 rsp=0x7ffff000
[I] sys : exit rc val=0x2a                    ← 42 in decimal
[proc] destroy pid=0xf name="ring3-hello-winapi"
[as] destroying pml4_phys=0x3d8000 regions=5
```

Five AS regions: PE headers page + .text page + .rdata page +
stack page + Win32 stubs page.

## Boot-time log (failure case, windows-kill.exe)

Same `[pe-resolve]` machinery, different outcome — the resolver
runs until it hits the first import we don't have a stub for
and bails:

```
[pe-resolve] UNRESOLVED dbghelp.dll!SymCleanup
[ring3] pe reject name="ring3-winkill" reason=ImportsPresent
```

This is the right behavior — a half-resolved IAT would leave
null slots that would `#PF` on the first call. The failure
surfaces in the log as a precise "this is the stub you'd need to
add next."

## Design decisions

### Why a shared stub page per process, not per DLL?

The "real" Windows layout is one loaded DLL per import source
(`kernel32.dll`, `ntdll.dll`, etc.), each with its own
`.text`, full export table, and a shared copy across all
processes. That's the right end-state but premature for v0:
it requires loading DLLs (which means resolving THEIR imports,
potentially recursively), binding the IAT to DLL export
addresses, and a reference-counted DLL cache.

v0 collapses all of this into a single per-process page of
trampolines. The resolver treats `{dll, func}` as an opaque
lookup key; if the lookup succeeds, we trampoline. There's no
real DLL, no export table, no reference counts. This is
correct-by-construction for any PE whose imports map 1:1 to
native syscalls, and trivially swappable when real DLLs land:
change `Win32StubsLookup` to walk a DLL export table instead
of a static array.

### Why patch the IAT from the kernel direct map, not from user?

Sections are mapped into the AS with their PE-specified flags.
`.rdata` (which contains the IAT) gets R + NX — not writable
to user. Three options for writing the IAT:

1. **Remap .rdata as writable during resolution.** Needs page-
   table flag manipulation + a TLB shootdown. Complex, and
   every `#PF` handler would have to understand "loading" as a
   transient state.
2. **Write to the physical frame through the kernel direct
   map.** The kernel's PML4 maps every usable frame as
   writable. `PhysToVirt(frame) + page_offset` is a writable
   kernel pointer regardless of the user's view. Zero flag
   manipulation, no TLB concerns for user PTEs.
3. **Defer resolution to first-call.** A "PLT stub" that
   triggers a syscall on first invocation, resolves, patches,
   then jumps. Real Windows does lazy-bind for delay-load
   imports. Too much plumbing for v0.

We picked (2). `AddressSpaceLookupUserFrame(as, va)` walks the
`regions` array (O(n), small n) and returns the physical
frame. No new page-table entries, no flag changes.

### Why reject on ANY unresolved import?

A PE's IAT is read by indirect jumps (`jmp *IAT_SLOT(%rip)`).
If a single slot is null (unresolved), the first call to that
function will `#PF` with `cr2 = 0`. A partially-resolved IAT
is a loaded-but-poisoned image. Reject whole-image on any
missing stub — the serial log lists the missing name so the
gap is visible.

A future slice may relax this for DLLs loaded by
`LoadLibrary` / `GetProcAddress`, where "missing function"
is a user-mode-visible failure. For static imports, zero
tolerance is correct.

## Stubs page layout (as of batch 7)

| Offset | Size | Name | Source batch |
|---|---|---|---|
| `0x00` | 9 | `ExitProcess` (+ `exit`, `_exit` via alias) | v0 |
| `0x09` | 3 | `GetStdHandle` | 1 |
| `0x0C` | 44 | `WriteFile` (+ `WriteConsoleA` alias) | 1 |
| `0x38` | 8 | `GetCurrentProcess` | 2 |
| `0x40` | 8 | `GetCurrentThread` | 2 |
| `0x48` | 8 | `GetCurrentProcessId` | 2 |
| `0x50` | 8 | `GetCurrentThreadId` | 2 |
| `0x58` | 9 | `TerminateProcess` | 2 |
| `0x61` | 8 | `GetLastError` | 3 |
| `0x69` | 10 | `SetLastError` | 3 |
| `0x74` | 18 | `InitializeCriticalSection`(`Ex`/`AndSpinCount`) | 4 |
| `0x86` | 1 | nop-ret (shared by CS Enter/Leave/Delete + CRT `_initterm` / `_cexit` / `_c_exit` / `_set_app_type` / `__setusermatherr`) | 4 + 6 |
| `0x87` | 45 | `memmove` (+ `memcpy` alias) | 5 |
| `0xB4` | 19 | `memset` | 5 |
| `0xC7` | 3 | return-0 (shared by 12 UCRT "report success" shims) | 6 |
| `0xCA` | 11 | `terminate` | 6 |
| `0xD5` | 11 | `_invalid_parameter_noinfo_noreturn` | 6 |
| `0xE0` | 29 | `strcmp` | 7 |
| `0xFD` | 17 | `strlen` | 7 |
| `0x10E` | 22 | `wcslen` | 7 |
| `0x124` | 23 | `strchr` | 7 |
| `0x13B` | 23 | `strcpy` | 7 |

Total: **0x152 bytes (338)** in a 4 KiB page. 3.65 KiB headroom.

20 unique stubs power ~45 distinct `{dll, func}` entries
in `kStubsTable` through aliasing.

## New syscalls introduced along the way

| # | Name | Batch | Semantics |
|---|---|---|---|
| 8 | `SYS_GETPROCID` | 2 | Returns `CurrentProcess()->pid` |
| 9 | `SYS_GETLASTERROR` | 3 | Returns `Process.win32_last_error` |
| 10 | `SYS_SETLASTERROR` | 3 | Writes `Process.win32_last_error`; returns previous value |

All are unprivileged (no cap check) — they only touch the
caller's own state.

## Cross-cutting infrastructure landed during the work

These aren't Win32-specific but were prerequisites surfaced by
the batches:

- **SSE enablement.** boot.S + ap_trampoline.S now set
  `CR0.MP=1`, `CR0.EM=0`, `CR4.OSFXSR=1`, `CR4.OSXMMEXCPT=1`.
  Without this, any ring-3 MOVUPS/MOVAPS `#UD`s (batch 5 was
  the first stub that exercised them — clang emits them for
  string-literal initialization).
- **rsp % 16 == 8 on ring-3 entry.** `Ring3UserEntry` biases
  the initial rsp by -8 so the entering function sees the
  same layout it would on a CALL. Matches both SysV and
  Microsoft x64 ABIs. Without this, any function with a
  `movaps [rsp+N]` in its prologue crashes.
- **`AddressSpaceLookupUserFrame`.** The PE loader needs to
  write to IAT slots that live on user-RO pages; this helper
  walks the AS regions array and returns the backing physical
  frame so the kernel can modify via `PhysToVirt`.

## What's next (deliberately deferred)

Ordered roughly by ROI for getting `windows-kill.exe` to run:

1. **Real user-mode heap.** `malloc` / `free` / `HeapAlloc` /
   `HeapCreate` / `HeapDestroy`. Requires per-process heap
   backing — either a new `SYS_BRK`-style syscall or a
   kernel-side VMO. Highest-ROI unblock: every non-trivial
   CRT function uses the heap transitively.

2. **`__p___argc` / `__p___argv` / `__p__commode`.** These
   return pointers to ints; the stub needs static storage on
   the stubs page itself (a few bytes of data after the code).
   Small work; deferred only because winkill currently fails
   before reaching them.

3. **Base relocation application.** Our loader rejects any PE
   with a non-empty `.reloc` directory. Walking
   `IMAGE_REL_BASED_DIR64` entries and adjusting absolute
   addresses by `actual_base - preferred_base` is ~40 lines.
   Unlocks loading any PE at a non-preferred ImageBase,
   including hostile images that can't be guaranteed a
   specific VA.

4. **TLS callback dispatch.** `windows-kill.exe` has a TLS
   directory (though the callback list is empty). A real Win32
   loader walks `AddressOfCallBacks` and invokes each with
   `DLL_PROCESS_ATTACH` before the entry point. Needed by any
   PE with C++ global ctors registered via TLS.

5. **Per-thread TEB.** GS-based TEB like real Windows, so the
   `GetLastError` / `SetLastError` stubs can read from
   `gs:[0x68]` directly instead of going through a syscall.
   Requires wiring `IA32_GS_BASE` MSR on context switch.
   Mostly a performance win; correctness works today.

6. **SEH dispatch.** `.pdata` + `.xdata` +
   `__C_specific_handler` — x64 structured exception
   handling. Only relevant once we run PEs that throw.
   Windows-kill doesn't throw in practice; deferred until a
   PE that does.

7. **Export-table-backed stubs.** Lay out a fake DLL image in
   memory (PE header + export directory + stubs), and have
   the resolver walk `IMAGE_EXPORT_DIRECTORY` like the real
   Windows loader. One step closer to loading third-party
   DLLs. Primarily refactoring — no new functionality until
   we actually need ordinal imports or GetProcAddress.

8. **Ordinal imports.** `WriteImpl` imports by ordinal
   (e.g. `@123`). Our resolver rejects them today. Would fall
   out naturally from (7).

9. **Wide-string intrinsics.** `wcscmp`, `wcscpy`, `wcschr`.
   Same shape as their narrow counterparts but with 2-byte
   stride. Batch 8 material if needed.

10. **More kernel32 surface.** A single big file of stubs
    covering `CreateFileW`, `ReadFile`, `CloseHandle`,
    `GetModuleHandle`, `GetProcAddress`, `LoadLibraryW`, etc.
    Each needs real kernel-side state (handle table, module
    list). Substantial; defer until we pick a specific PE to
    target.

## Related entries

- `pe-subsystem-v0.md` — the PE loader this builds on.
- `win32-subsystem-design.md` — the long-term architectural
  shape.
- `pentest-ring3-adversarial-v0.md` — the ring-3 task framework
  this all lives in.
