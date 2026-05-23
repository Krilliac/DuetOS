/*
 * kernel/util/string_erms.S
 *
 * Kernel-side memcpy / memmove / memset using ERMS (Enhanced REP
 * MOVSB / STOSB). Mirrors the userland equivalent in
 * userland/libc/src/string.S — same algorithm, same SysV AMD64
 * register convention, just a separate copy because the kernel
 * builds with a different toolchain set (`-mno-sse
 * -mgeneral-regs-only`) and does not link against libc.
 *
 * Replaces the hand-unrolled scalar paths previously in
 * string.cpp. rationale:
 *
 *   - The kernel runs under `-mno-sse`, so AVX/SSE memcpy is off
 *     the table — but `rep movsb` / `rep stosb` are
 *     general-purpose-integer instructions, fully legal under
 *     `-mgeneral-regs-only`.
 *   - On Ivy Bridge+ Intel and Bulldozer+ AMD (every CPU DuetOS
 *     targets today), `rep movsb` is a single microcoded
 *     operation that internally issues wide cached or
 *     write-combining stores with prefetch. It dominates a
 *     scalar 8-byte-unrolled loop for any copy ~128 bytes or
 *     larger, and ties or beats it for smaller copies thanks to
 *     fewer dispatched µops.
 *   - All three routines are called implicitly by the C++
 *     codegen (struct copies, zero-init, large literal inits)
 *     even with `-fno-builtin`, so they must be present at
 *     link time regardless of explicit caller count.
 *
 * Calling convention: SysV AMD64 — RDI = dst, RSI = src (or int
 * c for memset), RDX = byte count. Returns RAX = dst. Clobbers
 * RCX, RFLAGS, RDI, RSI. Other GPRs preserved.
 *
 * memmove handles overlap by direction: forward `rep movsb` when
 * dst < src or no overlap, backward `rep movsb` (DF=1) when
 * dst > src and the ranges overlap. cld at the end restores
 * DF=0 per the SysV ABI's "DF on call/return == 0" rule.
 *
 * No FPU / SIMD instructions — these run in any task on any CPU,
 * including before FPU bringup and in #PF / NMI / MCE handlers.
 */

    .intel_syntax noprefix
    .text

/* ------------------------------------------------------------------------- */
    .align 16
    .globl memcpy
    .type memcpy, @function
memcpy:
    /* RAX = dst (return value); RDI/RSI/RCX are the rep operands.
     * memcpy contract: regions do NOT overlap. Caller violations
     * are caller bugs; we don't bother with overlap detection. */
    mov     rax, rdi
    mov     rcx, rdx
    rep movsb
    ret
    .size memcpy, . - memcpy


/* -------------------------------------------------------------------------
 * memmove(dst, src, n)
 *
 * Forward `rep movsb` if dst <= src (no overlap, or overlap that
 * forward copy resolves correctly because dst is below the
 * source bytes). Backward `rep movsb` otherwise. cld on the
 * backward exit so the SysV-ABI "DF == 0 on return" rule holds.
 * ------------------------------------------------------------------------- */
    .align 16
    .globl memmove
    .type memmove, @function
memmove:
    mov     rax, rdi              /* return value */
    cmp     rdi, rsi
    je      .Lmemmove_done        /* same buffer — nothing to do */
    jb      .Lmemmove_forward     /* dst < src: forward copy is safe */

    /* dst > src: backward copy. */
    lea     rdi, [rdi + rdx - 1]
    lea     rsi, [rsi + rdx - 1]
    mov     rcx, rdx
    std
    rep movsb
    cld                            /* SysV ABI: DF must be 0 on return */
    ret

.Lmemmove_forward:
    mov     rcx, rdx
    rep movsb
.Lmemmove_done:
    ret
    .size memmove, . - memmove


/* -------------------------------------------------------------------------
 * memset(dst, c, n)
 *
 * SysV AMD64: rdi = dst, sil = c (low byte), rdx = n. `rep
 * stosb` writes AL byte-by-byte; rdi must end up consumed and
 * we want to return the ORIGINAL dst. Stash dst in r11 (caller-
 * saved scratch in SysV, identical to MS x64) so the rep
 * instruction can advance rdi freely.
 * ------------------------------------------------------------------------- */
    .align 16
    .globl memset
    .type memset, @function
memset:
    mov     r11, rdi              /* save original dst */
    movzx   eax, sil              /* AL = byte to store */
    mov     rcx, rdx              /* count */
    rep stosb                     /* while (rcx--) *rdi++ = al */
    mov     rax, r11              /* return original dst */
    ret
    .size memset, . - memset

/* GNU-stack note: this object does not need an executable stack.
 * Without the note the linker conservatively flags the whole
 * binary X-stack, which violates W^X. */
    .section .note.GNU-stack, "", @progbits
