/*
 * kernel/arch/aarch64/context_switch.S
 *
 * AArch64 thread context switch — save the outgoing thread's
 * callee-saved registers + SP + return address into its
 * KernelContext block, load the incoming thread's, then branch
 * back into the kernel scheduler.
 *
 *   void AArch64ContextSwitch(KernelContext* save,
 *                             KernelContext* load);
 *
 *   AAPCS64: x0 = save, x1 = load. We save only callee-saved
 *   registers (x19-x30 + d8-d15) since the caller's caller-saved
 *   registers are already volatile across this function call.
 *   d8-d15 (VFP/NEON callee-saved) are handled by the FPU-save-
 *   on-use scheme, NOT here — so a kernel-thread switch is GPR
 *   only.
 *
 * KernelContext layout (matches the C++ struct in
 * kernel/arch/aarch64/cpu.h once that lands; the order here is
 * the source of truth):
 *
 *   [+0x00] x19
 *   [+0x08] x20
 *   [+0x10] x21
 *   [+0x18] x22
 *   [+0x20] x23
 *   [+0x28] x24
 *   [+0x30] x25
 *   [+0x38] x26
 *   [+0x40] x27
 *   [+0x48] x28
 *   [+0x50] x29 (fp)
 *   [+0x58] x30 (lr)
 *   [+0x60] sp
 *   [+0x68] (reserved — alignment)
 *
 * 112 bytes total, 16-byte aligned. Adding TPIDR_EL0 / VFP
 * state pointers etc. is a later slice.
 *
 * GAP:
 *   - VFP/NEON state (d8-d15 are AAPCS64 callee-saved) — needs
 *     a save-on-use track separate from this fast path so
 *     non-FPU threads pay nothing.
 *   - TPIDR_EL0 / TPIDR_EL1 swap for TLS — when threads get
 *     thread-local storage.
 *   - SVE/SME state — Cortex-A510+ feature, deferred.
 */

    .section .text, "ax", %progbits

    .globl  AArch64ContextSwitch
    .type   AArch64ContextSwitch, %function
AArch64ContextSwitch:
    /* Save outgoing into [x0]. stp encodes (reg-pair, base+imm). */
    stp     x19, x20, [x0, #0x00]
    stp     x21, x22, [x0, #0x10]
    stp     x23, x24, [x0, #0x20]
    stp     x25, x26, [x0, #0x30]
    stp     x27, x28, [x0, #0x40]
    stp     x29, x30, [x0, #0x50]
    mov     x9, sp
    str     x9, [x0, #0x60]

    /* Load incoming from [x1]. */
    ldp     x19, x20, [x1, #0x00]
    ldp     x21, x22, [x1, #0x10]
    ldp     x23, x24, [x1, #0x20]
    ldp     x25, x26, [x1, #0x30]
    ldp     x27, x28, [x1, #0x40]
    ldp     x29, x30, [x1, #0x50]
    ldr     x9, [x1, #0x60]
    mov     sp, x9

    /* Resume on the loaded thread. x30 = the saved LR, so this
     * ret returns into whoever previously called us on that
     * thread's stack — i.e. the kernel scheduler's call site. */
    ret
    .size   AArch64ContextSwitch, . - AArch64ContextSwitch
