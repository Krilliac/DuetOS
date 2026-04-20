/*
 * CustomOS — ring-0 → ring-3 transition.
 *
 *   [[noreturn]] void EnterUserMode(u64 user_rip, u64 user_rsp);
 *
 * SysV AMD64 calling convention: rdi = user_rip, rsi = user_rsp.
 *
 * Contract (see usermode.h):
 *   - Caller already mapped `user_rip`'s code page with kPageUser + exec,
 *     and `user_rsp`'s stack page with kPageUser + write + NX.
 *   - Caller already called arch::TssSetRsp0(kernel_stack_top) so the next
 *     user→kernel transition lands on a valid kernel stack.
 *
 * The iretq frame pushed here is the canonical Intel SDM Vol. 3A §6.14.1
 * layout (SS / RSP / RFLAGS / CS / RIP, bottom to top in memory, highest
 * slot popped first). The RFLAGS value (0x202) sets IF=1 + the always-
 * set reserved bit 1, so the user task is immediately interruptible —
 * without that, the next timer tick could only land after the user code
 * itself sti'd, and ring-3 code has no privilege to sti.
 *
 * Segment-register hygiene: DS/ES/FS/GS are loaded with kUserDataSelector
 * BEFORE the iretq. iretq itself loads SS/CS from the frame; the other
 * four need to match the new privilege level or we'd enter ring 3 with
 * stale kernel-DS (which still works for data access but leaks kernel
 * selector state into ring 3 — considered a #GP accelerant on some
 * CPUs and generally bad posture).
 */

.intel_syntax noprefix

.section .text
.align 16
.global EnterUserMode
.type EnterUserMode, @function
EnterUserMode:
    /* Disable interrupts from the moment we start setting up segments.
     * A timer tick between "mov ds, ax" and "iretq" would deliver onto
     * the current kernel stack with the data segments half-swapped;
     * iretq on the way back then restores them cleanly. The iretq
     * frame's RFLAGS has IF=1, so interrupts re-enable atomically on
     * the ring-3 transition. */
    cli

    /* swapgs NOW, before we touch the GS selector. Rationale: in long
     * mode, `mov gs, <non-null sel>` reloads the hidden GSBASE from
     * the selected descriptor's base field. The user-data descriptor's
     * base is 0, so the mov below would ZERO GSBASE — and on the next
     * kernel entry (timer / syscall), any gs-relative read of per-CPU
     * state would fault against address 0. Instead, stash the kernel's
     * GSBASE into the KERNEL_GS_BASE MSR now; the isr_common entry
     * path's matching swapgs restores it on every trap from user. The
     * `mov gs, ax` that follows is free to zero GSBASE — that's the
     * value user mode sees, and KERNEL_GS_BASE preserves the kernel's
     * pcpu pointer across the round trip. */
    swapgs

    /* Load user data selector into DS/ES/FS/GS. The selector includes
     * RPL=3 (0x33); the CPU checks DPL == RPL for data segments loaded
     * outside of an iretq, which is why we don't just push zero here. */
    mov     ax, 0x33                /* kUserDataSelector */
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    /* SS is loaded by iretq from the frame — do NOT mov it here. */

    /* Build the iretq frame. In memory, lowest to highest:
     *   [rsp+0]  : RIP    <- user entry point
     *   [rsp+8]  : CS     <- kUserCodeSelector (0x2B)
     *   [rsp+16] : RFLAGS <- 0x202 (IF=1 + reserved bit 1)
     *   [rsp+24] : RSP    <- user stack pointer
     *   [rsp+32] : SS     <- kUserDataSelector (0x33)
     *
     * push order is reverse (SS first = highest, RIP last = lowest). */
    push    0x33                    /* SS = kUserDataSelector */
    push    rsi                     /* user RSP */
    push    0x202                   /* RFLAGS: IF=1, reserved=1 */
    push    0x2B                    /* CS = kUserCodeSelector */
    push    rdi                     /* user RIP */

    iretq

    /* Unreachable — iretq either enters user mode or #GPs. The ud2
     * is a belt-and-braces halt so an impossible fallthrough doesn't
     * silently execute whatever follows in the .text section. */
    ud2
.size EnterUserMode, . - EnterUserMode

/* NX stack — silence lld's PT_GNU_STACK warning. */
.section .note.GNU-stack, "", @progbits
