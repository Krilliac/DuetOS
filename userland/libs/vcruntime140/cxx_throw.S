/*
 * userland/libs/vcruntime140/cxx_throw.S
 *
 * ABI-preserving entry for MSVC's _CxxThrowException.  The C core
 * must receive the throwing caller's complete register state before
 * an optimized compiler prologue is allowed to reuse any volatile
 * or nonvolatile register.
 *
 * Microsoft x64 entry state:
 *   rcx = thrown object
 *   rdx = ThrowInfo
 *   [rsp] = caller RIP after `call _CxxThrowException`
 *   rsp+8 = caller RSP after that call returns
 *
 * The 0x508-byte frame starts with two unwind-described anonymous
 * 8-byte slots (entry RFLAGS and an alignment push), then contains
 * 0x20 bytes of call shadow space, a 16-byte-aligned 0x4d0-byte
 * Windows x64 CONTEXT, and 8 bytes of padding. R10 is volatile in
 * the Microsoft ABI, so its alignment push is deliberately described
 * as stack allocation rather than a nonvolatile-register save.
 */

    .text

    .globl  _CxxThrowException
    .def    _CxxThrowException; .scl 2; .type 32; .endef
    .seh_proc _CxxThrowException
_CxxThrowException:
    /* PUSH does not modify RFLAGS. Capture them before SUB/XOR or
     * any other flag-changing instruction, and describe the slot
     * as anonymous stack allocation to the Windows unwinder. */
    pushfq
    .seh_stackalloc 8
    pushq   %r10
    .seh_stackalloc 8
    subq    $0x4f8, %rsp
    .seh_stackalloc 0x4f8
    .seh_endprologue

    /* CONTEXT starts at rsp+0x20. Save all GPRs before using any
     * of them as scratch. */
    movq    %rax, 0x098(%rsp)
    movq    %rcx, 0x0a0(%rsp)
    movq    %rdx, 0x0a8(%rsp)
    movq    %rbx, 0x0b0(%rsp)
    movq    %rbp, 0x0c0(%rsp)
    movq    %rsi, 0x0c8(%rsp)
    movq    %rdi, 0x0d0(%rsp)
    movq    %r8,  0x0d8(%rsp)
    movq    %r9,  0x0e0(%rsp)
    movq    %r10, 0x0e8(%rsp)
    movq    %r11, 0x0f0(%rsp)
    movq    %r12, 0x0f8(%rsp)
    movq    %r13, 0x100(%rsp)
    movq    %r14, 0x108(%rsp)
    movq    %r15, 0x110(%rsp)

    /* CONTEXT.FltSave begins at context+0x100 = rsp+0x120.
     * FXSAVE64 records x87 state, MXCSR, and XMM0-XMM15. */
    fxsave64 0x120(%rsp)

    /* Fields not supplied by hardware are deterministic zeroes. */
    xorq    %rax, %rax
    movq    %rax, 0x020(%rsp)
    movq    %rax, 0x028(%rsp)
    movq    %rax, 0x030(%rsp)
    movq    %rax, 0x038(%rsp)
    movq    %rax, 0x040(%rsp)
    movq    %rax, 0x048(%rsp)
    movq    %rax, 0x068(%rsp)
    movq    %rax, 0x070(%rsp)
    movq    %rax, 0x078(%rsp)
    movq    %rax, 0x080(%rsp)
    movq    %rax, 0x088(%rsp)
    movq    %rax, 0x090(%rsp)

    movl    $0x0010000f, 0x050(%rsp)    /* AMD64 | CONTROL | INTEGER | SEGMENTS | FP */
    movl    0x138(%rsp), %eax           /* FXSAVE.MxCsr */
    movl    %eax, 0x054(%rsp)
    movw    %cs, 0x058(%rsp)
    movw    %ds, 0x05a(%rsp)
    movw    %es, 0x05c(%rsp)
    movw    %fs, 0x05e(%rsp)
    movw    %gs, 0x060(%rsp)
    movw    %ss, 0x062(%rsp)
    movq    0x500(%rsp), %rax           /* entry RFLAGS saved before the prologue */
    movl    %eax, 0x064(%rsp)

    leaq    0x510(%rsp), %rax
    movq    %rax, 0x0b8(%rsp)           /* caller RSP after the throw call */
    movq    0x508(%rsp), %rax
    movq    %rax, 0x118(%rsp)           /* caller RIP */

    leaq    0x020(%rsp), %r8            /* third arg: caller CONTEXT* */
    call    _CxxThrowExceptionImpl
    ud2
    .seh_endproc
