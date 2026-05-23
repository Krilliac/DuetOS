/*
 * kernel/arch/aarch64/syscall_entry.S
 *
 * AArch64 syscall entry — the SVC handler reached via the
 * "Lower EL using AArch64 / Synchronous" vector slot
 * (vectors+0x400) in exceptions.S. ESR_EL1.EC = 0x15 identifies
 * the synchronous cause as an SVC instruction; this file is
 * the dispatch from the generic SAVE_TRAP_FRAME+bl into a
 * syscall-specific handler that decodes the SVC immediate +
 * arguments and routes to the appropriate kernel TU.
 *
 * The convention (DuetOS-native, mirrors what AArch64 Linux
 * adopts):
 *
 *   x8     = syscall number
 *   x0..x5 = syscall args 0..5
 *   svc #0 = the trap (immediate ignored — number is in x8)
 *
 *   Return:
 *     x0 = syscall return value (negative for -errno on
 *          Linux-ABI subsystem; native ABI is its own thing).
 *     x1..x7 clobbered.
 *
 * GAP: the generic AArch64UserSyncException stub in exceptions.S
 * currently routes ALL EL0 synchronous exceptions to one C++
 * handler. Once that handler exists, it must inspect ESR_EL1.EC
 * and tail-call into AArch64SyscallDispatch (below) for
 * EC == 0x15 (SVC). Today there's no handler at all — this
 * file is the surface for the future split.
 *
 * STUB: AArch64SyscallDispatch is referenced but not yet
 * defined (the C++ side hasn't been written). The .S compiles
 * as a relocation against an external symbol; linking the
 * full AArch64 kernel won't work until the C++ handler lands.
 */

    .section .text, "ax", %progbits

/* -------------------------------------------------------------------------
 * AArch64SyscallEntry — fast-path syscall trampoline.
 *
 * Called from the AArch64UserSyncStub in exceptions.S WHEN
 * ESR_EL1.EC indicates an SVC. On entry:
 *
 *   - x0 holds the trap-frame pointer (SAVE_TRAP_FRAME's `mov
 *     x0, sp` argument).
 *   - The user GPRs x0..x30 are in the trap frame; x8 = syscall
 *     number, x0..x5 = args (per the convention above).
 *
 * We don't touch the trap frame itself here — we just read x8
 * back out, set up the C++ dispatcher's argument convention,
 * and tail-call into AArch64SyscallDispatch. The dispatcher
 * writes its return value back into x0's slot in the trap
 * frame, and AArch64UserSyncStub's RESTORE_TRAP_FRAME 1 +
 * ERET delivers it to user mode.
 *
 * AAPCS64 for the C++ side:
 *   x0 = TrapFrame*
 *   x1 = syscall number
 *   x2..x7 = args (copied from the trap frame's saved x0..x5
 *            slots for convenience; the C++ handler can also
 *            re-read from x0->user_x0 etc.)
 * ------------------------------------------------------------------------- */
    .globl  AArch64SyscallEntry
    .type   AArch64SyscallEntry, %function
AArch64SyscallEntry:
    /* x0 already = TrapFrame*. Load syscall nr from saved x8
     * (offset 0x40 in our frame — see exceptions.S layout). */
    ldr     x1, [x0, #0x40]
    /* Args 0..5 come from saved x0..x5 (offsets 0x00..0x28).
     * Pack them into x2..x7 so the C++ side sees them as plain
     * function args. */
    ldr     x2, [x0, #0x00]
    ldr     x3, [x0, #0x08]
    ldr     x4, [x0, #0x10]
    ldr     x5, [x0, #0x18]
    ldr     x6, [x0, #0x20]
    ldr     x7, [x0, #0x28]
    /* Tail-call. The C++ handler writes its return value into
     * the trap frame (via x0->user_x0) and returns; our caller
     * (AArch64UserSyncStub) then ERETs. */
    b       AArch64SyscallDispatch
    .size   AArch64SyscallEntry, . - AArch64SyscallEntry
