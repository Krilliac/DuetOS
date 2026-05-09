/*
 * DuetOS — userland setjmp / longjmp.
 *
 *   int  setjmp (jmp_buf env);
 *   void longjmp(jmp_buf env, int val);
 *
 * Both are fundamentally non-expressible in C — they have to read
 * the caller's RSP / RIP / non-volatile GPRs without depending on
 * the compiler's frame layout. Hand assembly is the only correct
 * implementation.
 *
 * jmp_buf layout (8-byte slots, total 64 bytes):
 *
 *   [ 0]  rbx       (callee-saved)
 *   [ 1]  rbp       (callee-saved)
 *   [ 2]  r12       (callee-saved)
 *   [ 3]  r13       (callee-saved)
 *   [ 4]  r14       (callee-saved)
 *   [ 5]  r15       (callee-saved)
 *   [ 6]  rsp       (caller's stack pointer, AFTER the call)
 *   [ 7]  rip       (return address — what setjmp's `ret` would jump to)
 *
 * The volatile GPRs (rax, rcx, rdx, rsi, rdi, r8-r11) are NOT
 * saved — by the C ABI, the caller doesn't expect them to survive
 * a function call anyway, so longjmp restoring them isn't
 * meaningful.
 *
 * setjmp returns 0 directly. longjmp(env, val) loads the saved
 * registers and jumps to the saved rip with rax = val (or 1 if
 * val == 0, since C requires setjmp to never appear to return 0
 * via longjmp).
 */

    .intel_syntax noprefix
    .text

/* ------------------------------------------------------------------------- */
    .align 16
    .globl setjmp
    .type setjmp, @function
setjmp:
    endbr64
    mov     [rdi +  0], rbx
    mov     [rdi +  8], rbp
    mov     [rdi + 16], r12
    mov     [rdi + 24], r13
    mov     [rdi + 32], r14
    mov     [rdi + 40], r15

    /* Caller's rsp = our rsp + 8 (one return address sits on top). */
    lea     rax, [rsp + 8]
    mov     [rdi + 48], rax

    /* Return address. */
    mov     rax, [rsp]
    mov     [rdi + 56], rax

    xor     eax, eax              /* return 0 on the direct path */
    ret
    .size setjmp, . - setjmp


/* ------------------------------------------------------------------------- */
    .align 16
    .globl longjmp
    .type longjmp, @function
longjmp:
    endbr64
    /* Spec: if val == 0, observed return value at the matching
     * setjmp must be 1, not 0 (otherwise the user couldn't tell
     * direct return from longjmp return). */
    mov     eax, esi
    test    eax, eax
    jne     .Llongjmp_have_val
    mov     eax, 1
.Llongjmp_have_val:

    mov     rbx, [rdi +  0]
    mov     rbp, [rdi +  8]
    mov     r12, [rdi + 16]
    mov     r13, [rdi + 24]
    mov     r14, [rdi + 32]
    mov     r15, [rdi + 40]

    /* Reconstruct a synthetic ret frame: write the saved RIP at
     * (saved_rsp - 8), switch to (saved_rsp - 8), then `ret`. The
     * `ret` pops the saved RIP and leaves RSP at the original
     * caller's position. */
    mov     rdx, [rdi + 48]       /* target rsp */
    mov     rcx, [rdi + 56]       /* target rip */
    sub     rdx, 8
    mov     [rdx], rcx
    mov     rsp, rdx
    ret
    .size longjmp, . - longjmp


    .section .note.GNU-stack, "", @progbits
