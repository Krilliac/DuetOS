# Win32 subsystem v0 — import resolution + kernel32.ExitProcess stub

**Type:** Observation · **Status:** Active · **Last updated:** 2026-04-21

## Context

The v0 PE loader (`pe-subsystem-v0.md`) could parse any real
Windows PE but only **execute** freestanding images with no
imports. This entry documents the next slice: running a PE that
imports `ExitProcess` from `kernel32.dll`, via a kernel-hosted
stub page. This is the first piece of a real Win32 subsystem —
the scaffolding that ntdll, kernel32, user32, etc. will plug
into as separate slices.

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

## Stubs table today

| DLL | Function | Stub offset | Semantics |
|-----|----------|------------|-----------|
| `kernel32.dll` | `ExitProcess` | 0x00 | `SYS_EXIT(rcx)` |

That's it. Everything else in the `windows-kill.exe` gap list
(kernel32's 35 other functions, ntdll, msvcp140, vcruntime140,
the UCRT api-sets, advapi32, dbghelp) is future work.
`Win32StubsLookup` returns false for everything else, and the
resolver logs `UNRESOLVED <dll>!<func>` and fails the load.

## What's next (deliberately deferred)

1. **More kernel32 stubs.** The three that are nearly free
   once we have a serial console path:
   - `GetStdHandle(DWORD id)` — return a fake handle (e.g.
     the `id` itself); used as the first arg to
     `WriteConsoleA`/`WriteFile`.
   - `WriteConsoleA(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID)`
     — thunk to `SYS_WRITE(1, buf, n)`. Ignores the LPDWORD
     (bytes-written) out-param for v0.
   - `WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID)` —
     if handle is 1 or 2, same as WriteConsoleA. Else fail.
   With these, we can have a proper Win32 "Hello, world" that
   prints via the Win32 API.

2. **GetLastError / SetLastError.** A per-TEB u32 slot. Needs
   a TEB (Thread Environment Block) per task — GS-based on
   Windows. For v0, could park in a per-process kernel-side
   `u32 last_error` and have stubs read/write it.

3. **Base relocations.** `hello_winapi.exe` has an empty
   `.reloc` (nothing to relocate — only rip-relative code and
   a static IAT slot). Any non-trivial PE has a real reloc
   table. Must land before we can relocate images off their
   preferred ImageBase.

4. **Multiple DLLs.** The stubs table is flat today; when
   two DLLs export the same function name (e.g.
   `CreateFileA` in both kernel32 and a compat shim), we need
   per-DLL sub-tables. Trivial change to the lookup loop.

5. **Export-table-backed stubs.** Instead of a hand-written
   kernel array, lay out a fake DLL image in memory (with a
   real PE header + export directory), and have the resolver
   walk `IMAGE_EXPORT_DIRECTORY` like the Windows loader
   does. One step closer to loading real DLLs.

6. **TLS callback dispatch.** `windows-kill.exe` has a TLS
   directory; MSVC-compiled PEs often do. A real Win32 loader
   walks `AddressOfCallBacks` and invokes each with
   `DLL_PROCESS_ATTACH` before the entry point.

7. **SEH dispatch.** `.pdata` + `.xdata` + `__C_specific_handler`
   — the whole x64 structured exception handling runtime. Only
   relevant once we run PEs that actually throw.

## Related entries

- `pe-subsystem-v0.md` — the PE loader this builds on.
- `win32-subsystem-design.md` — the long-term architectural
  shape.
- `pentest-ring3-adversarial-v0.md` — the ring-3 task framework
  this all lives in.
