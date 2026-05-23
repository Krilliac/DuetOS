/*
 * userland/libs/vcruntime140/chkstk.S
 *
 * vcruntime140.dll's __chkstk export — Microsoft x64 stack-probe
 * helper. MSVC's codegen sometimes emits `call __chkstk` that
 * resolves to vcruntime140 (vs ntdll) depending on import-library
 * order, and a runtime GetProcAddress("vcruntime140.dll",
 * "__chkstk") needs an actual export. The kernel-side thunk table
 * (kernel/subsystems/win32/thunks_table.inc) catches the at-load
 * IAT resolution today, but the DLL itself must also carry a real
 * body — otherwise the export shows up in the EAT as a null RVA
 * and any caller that bypasses the thunk table faults.
 *
 * This body is identical to ../ntdll/chkstk.S (the canonical
 * impl). Kept as a sibling file rather than via an include to
 * avoid plumbing a cross-DLL include path through the build
 * scripts; if you change one, audit both and re-run the
 * `objdump -d` byte-equivalence check. Both must stay aligned
 * with the kernel-side bytecode thunk at kOffChkStk in
 * kernel/subsystems/win32/thunks_bytecode.inc.
 *
 * ABI (Microsoft x64): RAX = bytes the caller is about to
 * subtract from RSP. On return: RAX preserved, RSP preserved
 * (caller does `sub rsp, rax` AFTER our return), R10/R11
 * clobbered (caller-saved scratch). Probes one byte per 4 KiB
 * stride from RSP-4096 down to RSP-RAX so any demand-paged
 * guard page faults here, not mid-prologue.
 */

    .text
    .globl  __chkstk
    .def    __chkstk; .scl 2; .type 32; .endef
__chkstk:
    pushq   %r10
    pushq   %r11
    movq    %rsp, %r11
    addq    $16, %r11               /* skip our two pushes — r11 = caller RSP at call */
    movq    %rax, %r10              /* r10 = bytes left to probe */
.Lloop:
    cmpq    $4096, %r10
    jbe     .Ldone
    subq    $4096, %r11
    subq    $4096, %r10
    testl   %r11d, (%r11)           /* probe one page (read; faults if guard) */
    jmp     .Lloop
.Ldone:
    subq    %r10, %r11              /* final partial-page address */
    testl   %r10d, (%r11)           /* probe final page */
    popq    %r11
    popq    %r10
    retq
