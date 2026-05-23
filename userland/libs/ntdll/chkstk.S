/*
 * userland/libs/ntdll/chkstk.S
 *
 * Microsoft x64 __chkstk — stack-probe helper.
 *
 * MSVC emits a `call __chkstk` at the head of any function whose
 * stack frame is >= 4 KiB. The contract (Microsoft x64 ABI):
 *
 *   In:    RAX = number of bytes the caller is about to subtract
 *                from RSP. Always a positive multiple of 8.
 *          RSP = points at our return address.
 *   Out:   RAX preserved.
 *          RSP preserved (the caller does `sub rsp, rax` after we
 *                         return — we do NOT adjust RSP ourselves).
 *          All GPRs preserved except R10/R11 (caller-saved scratch
 *          in the Win64 ABI). RFLAGS clobbered.
 *   Side:  Touch one byte per 4 KiB stride in the about-to-be-
 *          allocated range, so any demand-paged guard page in the
 *          range faults here (where the runtime can raise
 *          STATUS_STACK_OVERFLOW) rather than mid-prologue once
 *          RSP has already moved.
 *
 * DuetOS commits the entire user stack up front at PE load today,
 * so probing a committed page is a single dummy load the CPU
 * folds away. The probes are the forward-compatible shape: the
 * day demand-paged user stacks land, this thunk is already
 * correct.
 *
 * Mirrors the kernel-side bytecode thunk in
 * kernel/subsystems/win32/thunks_bytecode.inc (kOffChkStk). If
 * you change one, change the other and re-verify they agree byte
 * for byte on the algorithm.
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
    testl   %r11d, (%r11)           /* probe one page (read, faults if guard) */
    jmp     .Lloop
.Ldone:
    subq    %r10, %r11              /* final partial-page address */
    testl   %r10d, (%r11)           /* probe final page */
    popq    %r11
    popq    %r10
    retq
