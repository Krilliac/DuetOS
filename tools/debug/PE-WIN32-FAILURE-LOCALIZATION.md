# Localizing Win32 PE / Win32-subsystem failures in DuetOS

For pe-hello / pe-winapi / pe-winkill smoke regressions; for "PE imports
resolve but the call returns the wrong value"; for "kernel32.GetSomething
crashed in vcruntime140 memmove"; for NT-syscall STATUS_FOO drift; for
"my freshly-built PE faults at the entry of ntdll.dll!__guard_check_icall".

Win32 is the project's #2 pillar (per CLAUDE.md). Regressions here are
ABI breaks, NOT generic kernel bugs — they have their own diagnostic
signatures and methodology.

---

## PROMPT (paste verbatim)

```text
A Win32 PE is misbehaving in DuetOS — either the kernel triple-faulted
during PE execution, the PE got STATUS_ACCESS_VIOLATION at an address
inside an apparently-loaded DLL, or a kernel32/ntdll function returned
a value the PE didn't expect. Localize using the PE-failure methodology
in tools/debug/PE-WIN32-FAILURE-LOCALIZATION.md.

SYMPTOM:
  <paste the relevant smoke log section. Include:
   - The pe spawn line ([pe-loader] mapped ...).
   - Any [pe-imports] warnings about unresolved or stub-bound functions.
   - The fault: vector, CR2, RIP. If RIP is inside a DLL VA range, give
     the DLL base + offset.
   - The expected vs observed Win32 surface output (e.g. "[hello-winapi]
     printed via kernel32.WriteFile!" was expected, didn't fire).>

==========================================================================
STEP 1 — Identify what shape of failure.

  THUNK SURFACE GAP:
    PE imported `kernel32.SomeFunc`, the loader bound it to a stub
    (Win32-Surface-Status.md row reads STUB or MISSING), the stub
    returns 0 / E_NOTIMPL / -1, the PE's logic does the wrong thing.
    Signature: PE runs to completion but emits the wrong text / no
    text where it should.
    Inventory: `git grep -nE "// (STUB|GAP):"` for the function name.

  NT SYSCALL CONTRACT BREAK:
    kernel32 wrapper calls an Nt* syscall expecting STATUS_SUCCESS
    on a path the kernel now returns STATUS_INVALID_PARAMETER /
    ACCESS_VIOLATION (per PR #336's syscall-boundary slice — that
    PR INTENDED these to surface, but breaks PE consumers that
    relied on the prior silent success).
    Signature: PE crashes with a status code that didn't exist before
    OR a clearly-bogus return (e.g. NtAllocateVirtualMemory returns
    SUCCESS but *BaseAddress is nullptr).
    Recently-changed: kernel/syscall/syscall.cpp NtQueryInformationProcess,
    NtAllocateVirtualMemory, NtProtectVirtualMemory.

  LOST-SLOT COLLISION (relocations / image guards):
    Two DLLs land at colliding VAs (KASLR base alias) — second wins,
    first's callers fault at a valid-looking RIP inside what they
    THINK is the first DLL.
    Signature: ring-3 #GP/#UD/#PF at an address inside an imported
    DLL's range, RIP looks like real instructions of that DLL.
    Class precedent: vcruntime140 memmove crash (memory
    `serial-log-triage.md` class lost-page collision).

  SEH / EXCEPTION DISPATCH:
    Faulting PE was supposed to be caught by a try/except handler.
    NT KiUserExceptionDispatcher / RtlDispatchException calls into
    kernel SYS_SEH_DISPATCH. If that handler is broken, the PE
    aborts instead of recovering.
    Signature: pe-winkill fails (its whole point is exercising deadly
    faults that should be caught + reported). See
    kernel/subsystems/win32/seh_dispatch.cpp + userland/libs/ntdll/
    seh_trampolines.S.

  USERLAND DLL ITSELF BROKEN:
    A DLL whose source lives in userland/libs/<dll>/ has a real bug
    in the C/C++ implementation. Bind / run is fine; the bug is in
    the DLL's logic.
    Signature: trace logs from inside the DLL (KLOG_DEBUG_AV at the
    function entry) show wrong intermediate values.

==========================================================================
STEP 2 — Identify the binding state for every imported function.

  The PE loader emits one log line per import resolution. Search the
  smoke log:

  grep "pe-imports\|pe-loader" /mnt/c/Users/natew/AppData/Local/Temp/bringup-fail.log

  Cross-reference with wiki/reference/Win32-Surface-Status.md. Every
  STUB row that the PE imports is a potential cause.

==========================================================================
STEP 3 — Identify the RIP region.

  /usr/lib/llvm-18/bin/llvm-addr2line works for kernel ELF but NOT for
  loaded PE images. For PE-side RIPs, find the DLL base from
  `[pe-loader] mapped <dll> base=0x<va> size=0x<size>` lines in the
  smoke log, subtract base from RIP to get the offset, then look up
  the offset in the DLL's PE symbol map (if a .pdb or .map is in
  build/x86_64-debug/<dll>/).

  CLASS-OF-BUG shortcut:
    If RIP is inside guard_check_icall: indirect-call type-check
    failure (CFG-style). The function pointer being called isn't in
    the DLL's allowed-call set. Usually means an import was bound
    to the wrong thunk or the IAT got corrupted post-load.

==========================================================================
STEP 4 — Run with the PE-debug knob.

  cmake --preset x86_64-debug-redteam   # if available, escalates guards
  DUETOS_PE_TRACE=1 boot the smoke

  Or: add KLOG_DEBUG_S("loader/pe", "import", "name", import_name) at
  the binding site to see which thunks fired in which order.

==========================================================================
STEP 5 — Fix.

  Thunk gap: implement the real function (or a higher-fidelity stub
    that returns the success-shaped value the caller expects). Update
    Win32-Surface-Status.md row in the same commit.

  NT syscall break: revisit the syscall change. If the new return code
    is contract-correct (e.g. STATUS_INVALID_PARAMETER for a real bug),
    the PE's expectation was wrong — fix the PE-side caller. If the
    change was over-eager, narrow the kernel's new branch.

  Collision: re-roll KASLR bases (kernel/loader/pe_loader.cpp's randomise
    function). Add a collision detector that asserts no two loaded
    images share a VA range.

  SEH: add SerialWrite tracing in seh_dispatch.cpp at each branch.
    Most SEH bugs are in the dispatcher's classification of the fault
    record OR in the trampoline's stack layout.

==========================================================================
STEP 6 — Validate per smoke profile.

  for p in pe-hello pe-winapi pe-winkill; do
    for i in {1..10}; do
      bash tools/test/wsl-bringup-smoke.sh $p 2>&1 | tail -1
    done
  done
```

## Known signatures → known fixes

| Symptom | Likely class | First check |
|---|---|---|
| vcruntime140 memmove crash, valid-looking RIP | lost-slot collision | grep `base=0x...` for two PE/DLL VAs colliding |
| ntdll!__guard_check_icall fault | CFG mismatch | check IAT for binding to wrong thunk |
| pe-hello times out, no "[hello-pe]" line | thunk surface gap | check Win32-Surface-Status.md for kernel32 GetStdHandle/WriteFile rows |
| NtAlloc/Protect returns SUCCESS but ptr is 0 | post-PR#336 contract change | check 3b6ec236 syscall changes against caller expectations |
| pe-winkill never sees the catch-block sentinel | SEH dispatch broken | seh_dispatch.cpp trampoline-stack inspection |
