# Real-world PE execution — windows-kill.exe smoke

**Last updated:** 2026-04-22 (post argc/argv slice)
**Type:** Observation
**Status:** Active — winkill enters ring 3, runs CRT init through the
argc/argv read; the CRT now sees real pointers instead of dereferencing
the catch-all's zero. Next wall moves further into CRT startup.

## What changed (this slice)

Before this slice, `windows-kill.exe` (80 KB real MSVC PE: 8 sections,
52 imports across dbghelp / kernel32 / advapi32 / msvcp140 /
vcruntime140 / api-ms-win-crt-*, SEH, TLS, resource dir) was silently
rejected by the loader and never spawned. After this slice it:

1. Loads — every PE step succeeds (MapHeaders, MapSection×8,
   ApplyRelocations, stack×16, stubs page, ResolveImports×52, TEB).
2. Spawns a ring-3 task and enters CRT startup at its real entry
   point `0x140004070`.
3. Executes `__scrt_common_main_seh` and its helpers, walking dozens
   of bytes of MSVC CRT code.
4. Faults at the first import that returns NULL via our catch-all
   stub and the CRT then dereferences it (`mov rdx, [rdi]`).

Progress measurable at every boot — the `[pe-load]` step trace shows
exactly where each PE lands in the pipeline, and the `[task-kill]
ring-3 task took #PF` line tells you which unstubbed import is the
current next wall.

## Five gaps filled

1. **Catch-all import stub** — `win32::Win32StubsLookupCatchAll`
   points at the shared "xor eax,eax; ret" thunk. Previously any
   unknown import made `ResolveImports` return false and the loader
   bailed. Data imports (e.g. `std::cout` from MSVCP140.dll) now land
   on a NO-OP stub too; dereferencing them as data reads the xor/ret
   opcode bytes (garbage but not a #PF — the stubs page is R-X).
   Logged as `[pe-resolve] unknown import -> catch-all NO-OP` so
   they're easy to grep for.

2. **Frame-budget cap bump 32 → 128** — real PEs map far more pages
   than the freestanding test binary: winkill uses 8 sections × a few
   pages each + 16 stack pages + 1 TEB + 1 stubs + 16 heap pages + a
   few IAT frames. 32 was barely enough for a trivial hello_pe; 128 is
   the new committed budget (`kMaxUserVmRegionsPerAs` in
   `mm/address_space.h`). Region table is still a flat on-AS array, so
   cost is 128 × 16 bytes = 2 KiB per AS — well under a page.

3. **Stack: 16 pages + Win64 ABI rsp** — PE stack was one page at
   `kV0StackVa`. MSVC `__chkstk` probes the stack a page at a time
   during CRT startup; one page blew out on the first probe. Now 16
   pages (64 KiB) mapped ending at `kV0StackTop = 0x80000000`, and
   `SpawnPeFile` sets `proc->user_rsp_init = stack_top - 0x48` so the
   PE sees an `rsp = 16n + 8` with 32 bytes of shadow space above
   it — the Win64 ABI contract for a callee's entry.

4. **Minimal TEB + GSBASE load** — `EnterUserModeWithGs(rip, rsp,
   user_gs_base)` added alongside `EnterUserMode` (the old 2-arg form
   tails into it with `user_gs_base=0`, preserving native/Linux
   semantics). PE loads allocate a TEB page at `kV0TebVa =
   0x70000000`, write `NT_TIB.Self` at offset 0x30, and set
   `proc->user_gs_base = teb_va`. `EnterUserModeWithGs` does a
   `wrmsr MSR_GS_BASE` between the `mov gs, ax` (which zeroed gsbase
   via the descriptor load) and the `iretq`. This gets the PE past
   the CRT's `mov rax, gs:[0x30]` self-pointer read; further TEB
   fields (TLS array pointer, PEB ptr) stay zero so subsequent reads
   land at small linear addresses and fault visibly.

5. **GPR zero before iretq** — `EnterUserModeWithGs` scrubs rax,
   rbx, rcx, rdx, rbp, rsi, rdi, r8..r15 before `iretq`. Leaking
   kernel register state into ring 3 was (a) a spec violation for a
   process entry point and (b) caused CRT code that dereferences
   helper-return-value registers (`mov rdx, [rdi]` after
   `mov rdi, rax`) to fault when rdi held kernel state rather than
   `NULL`. Now the fault happens for the right reason — an unstubbed
   import returned 0 and the CRT dereferenced 0.

## The `[pe-load]` step trace

Every PE load now emits breadcrumbs:

```
[pe-load] begin status=ImportsPresent image_base=0x140000000 sections=0x8
[pe-load] step1 headers mapped
[pe-load] step2 sections mapped
[pe-load] step3 relocs applied
[pe-load] step4 stack mapped pages=0x10
[pe-load] step4b teb mapped va=0x70000000
[pe-load] step5 imports resolved
[pe-load] OK
```

Any failure logs the failing step (`FAIL MapSection idx=0x4`,
`FAIL ResolveImports`, `FAIL stack frame alloc idx=0x9`, …). Makes
the previously-silent "loader quietly rejected it" case unambiguous.

## Runtime miss-logger

Catch-all imports now route through a 35-byte trampoline at
`kOffMissLogger` in the stubs page instead of the bare
"xor eax,eax; ret". The trampoline decodes its caller's call
sequence:

  1. `[rsp]` is the return address after the PE's `call rel32`
     into an MSVC import thunk.
  2. `[rsp-4]` is the CALL's rel32 — thunk VA = `[rsp] + rel32`.
  3. The thunk is `FF 25 rel32_2` (`jmp qword [rip+rel32_2]`);
     IAT slot VA = `thunk + 6 + rel32_2`.

The trampoline passes the IAT slot VA to
`SYS_WIN32_MISS_LOG (16)`, which looks it up in
`CurrentProcess()->win32_iat_misses[]` (populated at load time
via `PeLoadDrainIatMisses`) and emits:

```
[win32-miss] slot=0x1400062c0 called fn="__p___argv"
[win32-miss] slot=0x1400062c8 called fn="__p___argc"
```

First winkill run after the slice prints exactly those two
lines before faulting at cr2=0 — the CRT is grabbing
pointers-to-argc/argv from MSVC's `__p___argc` / `__p___argv`
and dereferencing the zero they came back with. That's the
next wall: implement those two to return pointers to valid
argc/argv globals.

Why this beats static analysis: it tells us the *order of
calls*, so the first unimplemented import is always obvious
from the top of the log. Binary search through 24+ catch-alls
is not needed.

## Slice 25 — `__p___argc` / `__p___argv` + proc-env page

Follow-on to the miss-logger slice. The first two `[win32-miss]`
lines at every winkill boot were `__p___argv` and `__p___argc`;
the CRT reads these, gets 0 back from the catch-all, then
dereferences 0 and faults. This slice teaches the stubs to
return real pointers:

1. **Proc-env page** — new fixed VA `kProcEnvVa = 0x65000000`,
   one page, R-W + NX, mapped only for PEs with imports (same
   gate as the TEB page). Layout exposed via constants in
   `subsystems/win32/stubs.h`:

   ```
   0x00  int   argc   = 1
   0x08  char** argv  = kProcEnvVa + 0x20
   0x20  char* argv[] = { program_name_va, NULL }
   0x40  char  program_name[] = "a.exe\0"   (v0 placeholder)
   ```

   `Win32ProcEnvPopulate(page, name)` fills the layout. The PE
   loader allocates + zeroes the frame, calls the populator,
   and maps it between "step4b teb mapped" and "step5 imports
   resolved":

   ```
   [pe-load] step4c proc-env mapped va=0x65000000
   ```

2. **`__p___argc` / `__p___argv` stubs** — two 6-byte shims
   (`mov eax, imm32; ret`) at stub offsets `0x269` and `0x26F`.
   Immediate operands encode `kProcEnvVa + kProcEnvArgcOff`
   (= `0x65000000`) and `kProcEnvVa + kProcEnvArgvPtrOff`
   (= `0x65000008`) respectively. The 32-bit dest form zero-
   extends to rax — cheaper than a 10-byte movabs since both
   addresses fit in 32 bits.

3. **Registered under three DLL names** — the runtime apiset
   (`api-ms-win-crt-runtime-l1-1-0.dll`), ucrtbase, and msvcrt,
   covering the three link-path conventions the MSVC toolchain
   can produce.

4. **Layout static-asserted** — `static_assert`s in `stubs.cpp`
   tie the hand-assembled stub bytes to the public
   `kProcEnvVa / kProcEnvArgcOff / kProcEnvArgvPtrOff`
   constants. Moving the page VA or the field offsets without
   updating the stub bytes becomes a build-time error instead
   of a boot-time #PF.

The `a.exe` placeholder is deliberate v0. A future slice will
plumb the spawn-time program name through `PeLoad` so argv[0]
reflects the caller-specified name (`/bin/winkill.exe` etc.).
Minimal change today because the CRT only needs argv[0] to be
non-NULL + NUL-terminated; its contents matter only to code
that inspects argv[0] directly (rare).

## Slice 26 — data-import catch-all

After argc/argv landed, winkill ran past the CRT and reached
winkill's own `main()`. argc=1 → main takes the "no args"
branch which calls `std::cout << "usage...\n"`. Pre-slice-26,
`std::cout`'s IAT slot held the miss-logger's VA — reading
`[cout_iat]` produced the miss-logger's opcode bytes
(`0xfc48634824048b48`), which the CRT used as a vtable
pointer, producing a non-canonical #PF at cr2 = that bytes
value. Diagnosable only with a hex-to-asm rosetta sheet.

This slice adds:

1. **Data-import detection heuristic** in `subsystems/win32/stubs.h`:
   `IsLikelyDataImport(name)` returns true iff the name looks
   like MSVC's global-data mangling (`?name@scope@@3<type>...`).
   Walks to the first `@@` and checks the following byte for
   `'3'` (the storage-class letter for static-member/global).
   Functions use different class letters (`Q`, `A`, `B`, …), so
   they stay routed to the function miss-logger.

2. **`Win32StubsLookupDataCatchAll`** — returns
   `kProcEnvVa + kProcEnvDataMissOff = 0x65000800`. Dereferenced
   as a pointer, reads 0 (the proc-env page's tail is left zero
   by `Win32ProcEnvPopulate`). `[rax+offset]` then faults at
   `cr2 = offset` — a textbook null-pointer deref.

3. **PE loader routing** — `ResolveImports` picks
   `Win32StubsLookupDataCatchAll` vs `Win32StubsLookupCatchAll`
   based on the heuristic. Data imports do NOT stage an IAT-slot
   mapping in the miss-logger table (they're never called, so
   the translation table would be dead entries). Log line
   reflects the flavour: `unknown import -> data-miss zero pad`
   vs `unknown import -> catch-all NO-OP`.

Observed on winkill post-slice:

```
[pe-resolve] unknown import -> data-miss zero pad   fn="?cout@std@@3V..."
[task-kill] ring-3 task took #PF Page fault — terminating
  pid  : 0x18
  rip  : 0x14000142c                  ; same rip as before
  cr2  : 0x0000000000000004          ; was 0xfc48634824048b4c
```

Same instruction as the wall; infinitely cleaner fault
signature. Eleven other `?` symbols (widen, sputn, _Osfx, put,
setstate, flush, and four ostream::operator<< variants) stayed
on the function catch-all because their MSVC mangling begins
with `Q` (method) after `@@`, not `3`.

## Next walls (in execution order)

The current winkill fault is inside the CRT at `rip=0x14000400b`:

```
0x3ff8  mov rdi, rax         ; rdi = ret val of call to
                              ;        IAT thunk 0x4F4E (imported fn)
0x3ffb  call 0x4F48
0x4000  mov rbx, rax
0x4003  call 0x4F24          ;        IAT thunk 0x4F24
0x4008  mov r8, rax
0x400b  mov rdx, [rdi]       ; <-- FAULT: rdi==0 because the catch-all
                              ;    stub returned 0 from the import at 0x4F4E
```

Fixing this requires either:
- Identifying exactly which import at IAT slot 0x4F4E is expected to
  return a valid pointer (probably `GetCommandLineW` /
  `__acrt_iob_func` / similar) and giving it real semantics.
- Or detecting "CRT expects a pointer here" via heuristic (harder).

Past this: TLS array (`gs:[0x58]`), PEB (`gs:[0x60]`), SEH unwind
info walk, more kernel32 / vcruntime140 stubs. Each layer is now a
single-point fix rather than a "loader silently refused" dead end.

## Files touched in this slice

- `kernel/core/pe_loader.{h,cpp}` — step trace, 16-page stack, TEB
  alloc, `teb_va` in `PeLoadResult`, catch-all fallback, TlsPresent
  accepted.
- `kernel/core/ring3_smoke.cpp` — `SpawnPeFile` sets
  `user_rsp_init = stack_top - 0x48` + `user_gs_base = r.teb_va`,
  accepts `TlsPresent` validate, calls `EnterUserModeWithGs`.
- `kernel/core/process.{h,cpp}` — new `user_gs_base` field.
- `kernel/mm/address_space.h` — `kMaxUserVmRegionsPerAs` 32 → 128.
- `kernel/arch/x86_64/usermode.{h,S}` — `EnterUserModeWithGs`
  variant, MSR_GS_BASE load, GPR scrub, `EnterUserMode` tails in.
- `kernel/subsystems/win32/stubs.{h,cpp}` — `Win32StubsLookupCatchAll`.

## References

- `.claude/knowledge/pe-subsystem-v0.md` — freestanding PE loader
- `.claude/knowledge/win32-subsystem-v0.md` — import resolution +
  stubs table
- Intel SDM Vol. 3A §3.2.4 (MSR_GS_BASE), §6.14 (iretq frame).
- Microsoft x64 calling convention: rsp is `16n + 8` at callee
  entry, 32 bytes of caller-reserved shadow space above.
