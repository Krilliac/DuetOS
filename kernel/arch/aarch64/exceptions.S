/*
 * kernel/arch/aarch64/exceptions.S
 *
 * AArch64 exception vector table — installed in VBAR_EL1 by
 * boot.S. The hardware mandates a fixed layout: 16 entries of
 * 128 bytes each, 2 KiB aligned, organised as four groups of
 * four:
 *
 *   Offset  Source EL  SP        Cause
 *   0x000   Current    SP0       Synchronous
 *   0x080   Current    SP0       IRQ
 *   0x100   Current    SP0       FIQ
 *   0x180   Current    SP0       SError
 *   0x200   Current    SPx       Synchronous   ← kernel-mode exception (the common case)
 *   0x280   Current    SPx       IRQ           ← kernel-mode IRQ
 *   0x300   Current    SPx       FIQ
 *   0x380   Current    SPx       SError
 *   0x400   Lower      AArch64   Synchronous   ← user-mode SVC / data abort / etc.
 *   0x480   Lower      AArch64   IRQ           ← IRQ while user-mode runs
 *   0x500   Lower      AArch64   FIQ
 *   0x580   Lower      AArch64   SError
 *   0x600   Lower      AArch32   Synchronous   ← we don't target AArch32 user mode
 *   0x680   Lower      AArch32   IRQ
 *   0x700   Lower      AArch32   FIQ
 *   0x780   Lower      AArch32   SError
 *
 * Each entry is 128 bytes. We use the branch-to-common-handler
 * pattern: 32-bit `b` is enough for ±128 MiB of code reach, and
 * fits well within 128 bytes. The common handlers save the
 * trap frame, call into C++, restore, and ERET.
 *
 * GAP: every entry currently routes to the same dispatcher
 * stub. As the kernel grows, AArch64-side trap classification
 * (decode ESR_EL1.EC: SVC vs data abort vs instruction abort
 * vs MMU fault) and per-class handlers replace the unified
 * stub. The vector LAYOUT is correct already — only the
 * handler body grows.
 */

    .section .text.vectors, "ax", %progbits

/* The vector base MUST be 2 KiB aligned per the ARMv8-A ARM
 * spec. .balign 2048 emits the padding. */
    .balign 2048
    .globl  vectors
    .type   vectors, %function
vectors:
    /* Current EL with SP0 — Synchronous / IRQ / FIQ / SError.
     * SP0 means SP_EL0 is the kernel SP, which is unusual; we
     * typically run kernel code with SPSel=1 (SP_EL1). These
     * entries fire only if SPSel was explicitly set to 0,
     * which would be a kernel bug; route them all to the
     * "unhandled" stub so any unexpected SP0 use is loud. */
    b       AArch64UnhandledExceptionStub
    .balign 128
    b       AArch64UnhandledExceptionStub
    .balign 128
    b       AArch64UnhandledExceptionStub
    .balign 128
    b       AArch64UnhandledExceptionStub

    /* Current EL with SPx — kernel-mode normal case. */
    .balign 128
    b       AArch64KernelSyncStub          /* 0x200: kernel-mode synchronous */
    .balign 128
    b       AArch64KernelIrqStub           /* 0x280: kernel-mode IRQ */
    .balign 128
    b       AArch64KernelFiqStub           /* 0x300: kernel-mode FIQ */
    .balign 128
    b       AArch64KernelSErrorStub        /* 0x380: kernel-mode SError */

    /* Lower EL using AArch64 — user-mode entry. */
    .balign 128
    b       AArch64UserSyncStub            /* 0x400: SVC / data abort from EL0 */
    .balign 128
    b       AArch64UserIrqStub             /* 0x480: IRQ while at EL0 */
    .balign 128
    b       AArch64UserFiqStub             /* 0x500: FIQ while at EL0 */
    .balign 128
    b       AArch64UserSErrorStub          /* 0x580: SError from EL0 */

    /* Lower EL using AArch32 — DuetOS does not run AArch32
     * userland, so any entry here is a misroute. */
    .balign 128
    b       AArch64UnhandledExceptionStub
    .balign 128
    b       AArch64UnhandledExceptionStub
    .balign 128
    b       AArch64UnhandledExceptionStub
    .balign 128
    b       AArch64UnhandledExceptionStub
    .balign 128
    /* End-of-table marker — the next .balign 2048 in any TU
     * after us would clobber overflow if we accidentally grew
     * past 16 entries. */
    .size   vectors, . - vectors

/* -------------------------------------------------------------------------
 * Common stubs. Each saves the 31 GPRs to the stack, captures
 * ELR/SPSR/ESR/FAR (the AArch64 trap-frame essentials), calls
 * a C++ handler, then restores and ERETs.
 *
 * The trap frame layout (top-of-stack first, growing down by
 * pushes — AArch64 grows toward lower addresses):
 *
 *   [sp + 0x00] x0
 *   [sp + 0x08] x1
 *    ...
 *   [sp + 0xF0] x30
 *   [sp + 0xF8] sp_el0                (user SP if from EL0)
 *   [sp +0x100] elr_el1               (return address)
 *   [sp +0x108] spsr_el1              (saved PSTATE)
 *   [sp +0x110] esr_el1               (exception syndrome)
 *   [sp +0x118] far_el1               (fault address; valid only for data/instr aborts)
 *
 * Total: 36 × 8 = 288 bytes. Aligned to 16 (stack ABI).
 *
 * AArch64UnhandledExceptionStub is the "this shouldn't happen"
 * sink. AArch64Kernel* / AArch64User* dispatch to per-source
 * C++ handlers (KernelTrapAArch64 / UserTrapAArch64) once those
 * exist.
 * ------------------------------------------------------------------------- */

    .section .text, "ax", %progbits

    .macro SAVE_TRAP_FRAME from_user
    sub     sp, sp, #288
    stp     x0,  x1,  [sp, #0x00]
    stp     x2,  x3,  [sp, #0x10]
    stp     x4,  x5,  [sp, #0x20]
    stp     x6,  x7,  [sp, #0x30]
    stp     x8,  x9,  [sp, #0x40]
    stp     x10, x11, [sp, #0x50]
    stp     x12, x13, [sp, #0x60]
    stp     x14, x15, [sp, #0x70]
    stp     x16, x17, [sp, #0x80]
    stp     x18, x19, [sp, #0x90]
    stp     x20, x21, [sp, #0xA0]
    stp     x22, x23, [sp, #0xB0]
    stp     x24, x25, [sp, #0xC0]
    stp     x26, x27, [sp, #0xD0]
    stp     x28, x29, [sp, #0xE0]
    .if \from_user
        mrs     x9, sp_el0             /* capture user SP from EL0 */
        stp     x30, x9, [sp, #0xF0]
    .else
        /* Kernel-mode entry: SP came from SP_EL1; bypass the
         * sp_el0 capture and let the slot show the kernel SP
         * the trap entered with (caller's SP, i.e. sp + 288). */
        add     x9, sp, #288
        stp     x30, x9, [sp, #0xF0]
    .endif
    mrs     x9,  elr_el1
    mrs     x10, spsr_el1
    stp     x9,  x10, [sp, #0x100]
    mrs     x9,  esr_el1
    mrs     x10, far_el1
    stp     x9,  x10, [sp, #0x110]
    .endm

    .macro RESTORE_TRAP_FRAME to_user
    ldp     x9,  x10, [sp, #0x100]
    msr     elr_el1,  x9
    msr     spsr_el1, x10
    .if \to_user
        ldp     x30, x9, [sp, #0xF0]
        msr     sp_el0, x9
    .else
        ldr     x30, [sp, #0xF0]
        /* SP_EL1 restore is implicit via the add at the end. */
    .endif
    ldp     x28, x29, [sp, #0xE0]
    ldp     x26, x27, [sp, #0xD0]
    ldp     x24, x25, [sp, #0xC0]
    ldp     x22, x23, [sp, #0xB0]
    ldp     x20, x21, [sp, #0xA0]
    ldp     x18, x19, [sp, #0x90]
    ldp     x16, x17, [sp, #0x80]
    ldp     x14, x15, [sp, #0x70]
    ldp     x12, x13, [sp, #0x60]
    ldp     x10, x11, [sp, #0x50]
    ldp     x8,  x9,  [sp, #0x40]
    ldp     x6,  x7,  [sp, #0x30]
    ldp     x4,  x5,  [sp, #0x20]
    ldp     x2,  x3,  [sp, #0x10]
    ldp     x0,  x1,  [sp, #0x00]
    add     sp, sp, #288
    eret
    .endm

    .globl  AArch64UnhandledExceptionStub
    .type   AArch64UnhandledExceptionStub, %function
AArch64UnhandledExceptionStub:
    SAVE_TRAP_FRAME 0
    mov     x0, sp                          /* arg0 = TrapFrame* */
    bl      AArch64UnhandledException       /* C++ handler; STUB body lives in arch/aarch64/traps.cpp once written */
    RESTORE_TRAP_FRAME 0
    .size   AArch64UnhandledExceptionStub, . - AArch64UnhandledExceptionStub

    .globl  AArch64KernelSyncStub
    .type   AArch64KernelSyncStub, %function
AArch64KernelSyncStub:
    SAVE_TRAP_FRAME 0
    mov     x0, sp
    bl      AArch64KernelSyncException
    RESTORE_TRAP_FRAME 0
    .size   AArch64KernelSyncStub, . - AArch64KernelSyncStub

    .globl  AArch64KernelIrqStub
    .type   AArch64KernelIrqStub, %function
AArch64KernelIrqStub:
    SAVE_TRAP_FRAME 0
    mov     x0, sp
    bl      AArch64KernelIrq
    RESTORE_TRAP_FRAME 0
    .size   AArch64KernelIrqStub, . - AArch64KernelIrqStub

    .globl  AArch64KernelFiqStub
    .type   AArch64KernelFiqStub, %function
AArch64KernelFiqStub:
    SAVE_TRAP_FRAME 0
    mov     x0, sp
    bl      AArch64KernelFiq
    RESTORE_TRAP_FRAME 0
    .size   AArch64KernelFiqStub, . - AArch64KernelFiqStub

    .globl  AArch64KernelSErrorStub
    .type   AArch64KernelSErrorStub, %function
AArch64KernelSErrorStub:
    SAVE_TRAP_FRAME 0
    mov     x0, sp
    bl      AArch64KernelSError
    RESTORE_TRAP_FRAME 0
    .size   AArch64KernelSErrorStub, . - AArch64KernelSErrorStub

    .globl  AArch64UserSyncStub
    .type   AArch64UserSyncStub, %function
AArch64UserSyncStub:
    SAVE_TRAP_FRAME 1
    mov     x0, sp
    bl      AArch64UserSyncException        /* SVC dispatch lives here once syscall plumbing arrives */
    RESTORE_TRAP_FRAME 1
    .size   AArch64UserSyncStub, . - AArch64UserSyncStub

    .globl  AArch64UserIrqStub
    .type   AArch64UserIrqStub, %function
AArch64UserIrqStub:
    SAVE_TRAP_FRAME 1
    mov     x0, sp
    bl      AArch64UserIrq
    RESTORE_TRAP_FRAME 1
    .size   AArch64UserIrqStub, . - AArch64UserIrqStub

    .globl  AArch64UserFiqStub
    .type   AArch64UserFiqStub, %function
AArch64UserFiqStub:
    SAVE_TRAP_FRAME 1
    mov     x0, sp
    bl      AArch64UserFiq
    RESTORE_TRAP_FRAME 1
    .size   AArch64UserFiqStub, . - AArch64UserFiqStub

    .globl  AArch64UserSErrorStub
    .type   AArch64UserSErrorStub, %function
AArch64UserSErrorStub:
    SAVE_TRAP_FRAME 1
    mov     x0, sp
    bl      AArch64UserSError
    RESTORE_TRAP_FRAME 1
    .size   AArch64UserSErrorStub, . - AArch64UserSErrorStub
