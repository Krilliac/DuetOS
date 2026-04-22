# Real-world PE execution — windows-kill.exe smoke

**Last updated:** 2026-04-22
**Type:** Observation
**Status:** Active — winkill now enters ring 3, runs CRT init, faults on
first unstubbed import return value. Five previously silent loader-level
gaps now visible + fixed.

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
