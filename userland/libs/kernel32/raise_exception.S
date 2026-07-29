/*
 * userland/libs/kernel32/raise_exception.S
 *
 * ABI-preserving entry for kernel32!RaiseException.
 *
 * RaiseException must dispatch a software exception AT THE CALLER'S
 * location: the frame walk in ntdll's KiUserExceptionDispatcher
 * starts from the CONTEXT we hand it, so that CONTEXT has to be the
 * caller's state, not ours.  Capturing it here — before any compiler
 * prologue can reuse a volatile or nonvolatile register — is the same
 * reason vcruntime140's cxx_throw.S exists, and this file is
 * deliberately its twin.  Getting the caller's frame rather than our
 * own also means RaiseException itself never has to be unwindable.
 *
 * Microsoft x64 entry state:
 *   ecx = dwExceptionCode
 *   edx = dwExceptionFlags
 *   r8d = nNumberOfArguments
 *   r9  = lpArguments
 *   [rsp]   = caller RIP after `call RaiseException`
 *   rsp+8   = caller RSP after that call returns
 *
 * The 0x518-byte frame starts with two unwind-described anonymous
 * 8-byte slots (entry RFLAGS and an alignment push), then 0x30 bytes
 * of outgoing-argument space (0x20 call shadow + the fifth argument
 * at +0x20 + 8 bytes of pad to keep the CONTEXT 16-byte aligned), a
 * 16-byte-aligned 0x4d0-byte Windows x64 CONTEXT, and 8 bytes of
 * tail padding.  R10 is volatile in the Microsoft ABI, so its
 * alignment push is deliberately described as stack allocation
 * rather than a nonvolatile-register save.
 *
 * RaiseExceptionImpl does not return when a handler claims the
 * exception.  A filter answering EXCEPTION_CONTINUE_EXECUTION does
 * not come back here either: ntdll restores the captured CONTEXT,
 * whose RIP/RSP are the caller's, so control lands past our epilogue
 * exactly as if RaiseException had returned.  The epilogue is still
 * real because RaiseExceptionImpl returns normally when the caller's
 * arguments are rejected.
 */

    .text

    .globl  RaiseException
    .def    RaiseException; .scl 2; .type 32; .endef
    .seh_proc RaiseException
RaiseException:
    /* PUSH does not modify RFLAGS. Capture them before SUB/XOR or
     * any other flag-changing instruction, and describe the slot
     * as anonymous stack allocation to the Windows unwinder. */
    pushfq
    .seh_stackalloc 8
    pushq   %r10
    .seh_stackalloc 8
    subq    $0x518, %rsp
    .seh_stackalloc 0x518
    .seh_endprologue

    /* CONTEXT starts at rsp+0x30. Save all GPRs before using any
     * of them as scratch. */
    movq    %rax, 0x0a8(%rsp)
    movq    %rcx, 0x0b0(%rsp)
    movq    %rdx, 0x0b8(%rsp)
    movq    %rbx, 0x0c0(%rsp)
    movq    %rbp, 0x0d0(%rsp)
    movq    %rsi, 0x0d8(%rsp)
    movq    %rdi, 0x0e0(%rsp)
    movq    %r8,  0x0e8(%rsp)
    movq    %r9,  0x0f0(%rsp)
    movq    %r10, 0x0f8(%rsp)
    movq    %r11, 0x100(%rsp)
    movq    %r12, 0x108(%rsp)
    movq    %r13, 0x110(%rsp)
    movq    %r14, 0x118(%rsp)
    movq    %r15, 0x120(%rsp)

    /* CONTEXT.FltSave begins at context+0x100 = rsp+0x130.
     * FXSAVE64 records x87 state, MXCSR, and XMM0-XMM15. */
    fxsave64 0x130(%rsp)

    /* Fields not supplied by hardware are deterministic zeroes. */
    xorq    %rax, %rax
    movq    %rax, 0x030(%rsp)
    movq    %rax, 0x038(%rsp)
    movq    %rax, 0x040(%rsp)
    movq    %rax, 0x048(%rsp)
    movq    %rax, 0x050(%rsp)
    movq    %rax, 0x058(%rsp)
    movq    %rax, 0x078(%rsp)
    movq    %rax, 0x080(%rsp)
    movq    %rax, 0x088(%rsp)
    movq    %rax, 0x090(%rsp)
    movq    %rax, 0x098(%rsp)
    movq    %rax, 0x0a0(%rsp)

    movl    $0x0010000f, 0x060(%rsp)    /* AMD64 | CONTROL | INTEGER | SEGMENTS | FP */
    movl    0x148(%rsp), %eax           /* FXSAVE.MxCsr */
    movl    %eax, 0x064(%rsp)
    movw    %cs, 0x068(%rsp)
    movw    %ds, 0x06a(%rsp)
    movw    %es, 0x06c(%rsp)
    movw    %fs, 0x06e(%rsp)
    movw    %gs, 0x070(%rsp)
    movw    %ss, 0x072(%rsp)
    movq    0x510(%rsp), %rax           /* entry RFLAGS saved before the prologue */
    movl    %eax, 0x074(%rsp)

    leaq    0x520(%rsp), %rax
    movq    %rax, 0x0c8(%rsp)           /* caller RSP after the RaiseException call */
    movq    0x518(%rsp), %rax
    movq    %rax, 0x128(%rsp)           /* caller RIP */

    /* RaiseExceptionImpl(code, flags, nargs, args, caller CONTEXT*).
     * rcx/rdx/r8/r9 already hold the first four; the fifth goes in
     * the outgoing-argument slot just past the call shadow space. */
    leaq    0x030(%rsp), %rax
    movq    %rax, 0x20(%rsp)
    call    RaiseExceptionImpl

    addq    $0x518, %rsp
    popq    %r10
    popfq
    retq
    .seh_endproc
