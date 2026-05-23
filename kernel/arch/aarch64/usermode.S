/*
 * kernel/arch/aarch64/usermode.S
 *
 * Drop from EL1 (kernel) to EL0 (user) with a given user PC +
 * user SP. Used by the spawn path to launch the first user
 * instruction of a freshly-loaded ELF.
 *
 *   [[noreturn]] void AArch64EnterUserMode(u64 user_pc,
 *                                          u64 user_sp);
 *
 *   AAPCS64: x0 = user PC, x1 = user SP. Never returns from
 *   kernel side — control transfers to user code via ERET, and
 *   the kernel only sees this thread again when an exception
 *   re-enters via VBAR_EL1.
 *
 * Mechanism:
 *   - ELR_EL1 = user PC (where ERET resumes execution).
 *   - SP_EL0 = user SP (the user-mode stack the new thread
 *              wakes up on).
 *   - SPSR_EL1 = a saved PSTATE that decodes to EL0t (use SP_EL0)
 *                with DAIF cleared (interrupts on once at EL0).
 *                Bits: M[4:0] = 0b00000 (EL0t), F=0, I=0, A=0,
 *                D=0, plus a sensible defaults set.
 *
 * SPSR_EL1 bits we care about:
 *   [31:28]  NZCV       — carry over caller's flags (zero is fine)
 *   [22:23]  IL, SS     — illegal/single-step; leave 0
 *   [9]      D          — debug mask; 0 (debug exceptions allowed)
 *   [8]      A          — SError mask; 0
 *   [7]      I          — IRQ mask; 0 (IRQs enabled at EL0)
 *   [6]      F          — FIQ mask; 0
 *   [3:0]    M[4:0]     — mode = 0b0000 (EL0t)
 *
 * Final SPSR_EL1 value: 0x0 (everything cleared, mode = EL0t).
 * If a future slice wants user-mode FIQs off but IRQs on, flip
 * F=1 here.
 */

    .section .text, "ax", %progbits

    .globl  AArch64EnterUserMode
    .type   AArch64EnterUserMode, %function
AArch64EnterUserMode:
    msr     elr_el1,  x0                   /* user PC */
    msr     sp_el0,   x1                   /* user SP */
    mov     x2, xzr                        /* SPSR_EL1: EL0t, DAIF cleared */
    msr     spsr_el1, x2

    /* Wipe caller-saved scratch so user code can't observe
     * leftover kernel state on entry. Callee-saved regs are
     * the user-mode ABI's "preserved on syscall return" set,
     * which IS what user expects to see — we deliberately
     * leave x19-x30 + sp alone here. For a fresh-spawn the
     * caller (spawn.cpp) has typically already zeroed them. */
    mov     x0, xzr
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x4, xzr
    mov     x5, xzr
    mov     x6, xzr
    mov     x7, xzr
    mov     x8, xzr
    mov     x9, xzr
    mov     x10, xzr
    mov     x11, xzr
    mov     x12, xzr
    mov     x13, xzr
    mov     x14, xzr
    mov     x15, xzr
    mov     x16, xzr
    mov     x17, xzr
    mov     x18, xzr

    eret                                   /* drop to EL0, jump to ELR_EL1 */
    .size   AArch64EnterUserMode, . - AArch64EnterUserMode
