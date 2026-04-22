/*
 * CustomOS — CPU exception stubs for vectors 0..31.
 *
 * Each stub normalizes the interrupt frame so the C++ dispatcher sees a
 * uniform TrapFrame regardless of whether the CPU pushed an error code.
 * Vectors that don't push their own error code push a zero in its place.
 *
 * TrapFrame layout (matches traps.h):
 *
 *   [low addr]  r15, r14, r13, r12, r11, r10, r9, r8,
 *               rbp, rdi, rsi, rdx, rcx, rbx, rax,
 *               vector, error_code,
 *               rip, cs, rflags, rsp, ss   [high addr]
 */

.intel_syntax noprefix

/* -------------------------------------------------------------------------
 * Stub macros.
 * ------------------------------------------------------------------------- */

.macro ISR_NOERR vec
    .align 16
    .global isr_\vec
isr_\vec:
    /* endbr64 for IBT — every IDT entry points at one of these
     * labels and the CPU treats IDT dispatch as an indirect branch.
     * Without an endbr landing pad, each interrupt would raise #CP
     * instead of running the handler. Emits as a 4-byte NOP on
     * pre-CET CPUs. */
    endbr64
    push    0                   /* fake error code      */
    push    \vec                /* vector number        */
    jmp     isr_common
.endm

.macro ISR_ERR vec
    .align 16
    .global isr_\vec
isr_\vec:
    endbr64
    /* CPU already pushed the error code. */
    push    \vec                /* vector number        */
    jmp     isr_common
.endm

/* -------------------------------------------------------------------------
 * The 32 architecturally-defined exception vectors. The set that pushes an
 * error code (8, 10, 11, 12, 13, 14, 17, 21, 29, 30) matches the Intel SDM.
 * ------------------------------------------------------------------------- */
.section .text

ISR_NOERR 0                     /* #DE Divide-by-zero       */
ISR_NOERR 1                     /* #DB Debug                */
ISR_NOERR 2                     /* NMI                      */
ISR_NOERR 3                     /* #BP Breakpoint (int3)    */
ISR_NOERR 4                     /* #OF Overflow             */
ISR_NOERR 5                     /* #BR BOUND range exceeded */
ISR_NOERR 6                     /* #UD Invalid opcode       */
ISR_NOERR 7                     /* #NM Device not available */
ISR_ERR   8                     /* #DF Double fault         */
ISR_NOERR 9                     /* Coprocessor overrun (legacy) */
ISR_ERR   10                    /* #TS Invalid TSS          */
ISR_ERR   11                    /* #NP Segment not present  */
ISR_ERR   12                    /* #SS Stack-segment fault  */
ISR_ERR   13                    /* #GP General protection   */
ISR_ERR   14                    /* #PF Page fault           */
ISR_NOERR 15                    /* Reserved                 */
ISR_NOERR 16                    /* #MF x87 FP exception     */
ISR_ERR   17                    /* #AC Alignment check      */
ISR_NOERR 18                    /* #MC Machine check        */
ISR_NOERR 19                    /* #XM SIMD FP exception    */
ISR_NOERR 20                    /* #VE Virtualization       */
ISR_ERR   21                    /* #CP Control protection   */
ISR_NOERR 22                    /* Reserved                 */
ISR_NOERR 23                    /* Reserved                 */
ISR_NOERR 24                    /* Reserved                 */
ISR_NOERR 25                    /* Reserved                 */
ISR_NOERR 26                    /* Reserved                 */
ISR_NOERR 27                    /* Reserved                 */
ISR_NOERR 28                    /* #HV Hypervisor injection */
ISR_ERR   29                    /* #VC VMM communication    */
ISR_ERR   30                    /* #SX Security exception   */
ISR_NOERR 31                    /* Reserved                 */


/* -------------------------------------------------------------------------
 * Hardware IRQ vectors. The 8259 PIC and LAPIC are remapped so that IRQs
 * 0..15 land at vectors 32..47. None of these push an error code (only the
 * exception subset architecturally does), so they all use the NOERR macro.
 * The dispatcher distinguishes IRQ from exception by frame->vector >= 32.
 *
 * In a CustomOS system the legacy 8259 PIC is masked (see pic.cpp); these
 * vectors are driven by the LAPIC and, when enabled, the IOAPIC.
 * ------------------------------------------------------------------------- */
ISR_NOERR 32                    /* IRQ0  — LAPIC timer (periodic tick) */
ISR_NOERR 33                    /* IRQ1                                */
ISR_NOERR 34                    /* IRQ2                                */
ISR_NOERR 35                    /* IRQ3                                */
ISR_NOERR 36                    /* IRQ4                                */
ISR_NOERR 37                    /* IRQ5                                */
ISR_NOERR 38                    /* IRQ6                                */
ISR_NOERR 39                    /* IRQ7  — also the 8259 spurious slot */
ISR_NOERR 40                    /* IRQ8                                */
ISR_NOERR 41                    /* IRQ9                                */
ISR_NOERR 42                    /* IRQ10                               */
ISR_NOERR 43                    /* IRQ11                               */
ISR_NOERR 44                    /* IRQ12                               */
ISR_NOERR 45                    /* IRQ13                               */
ISR_NOERR 46                    /* IRQ14                               */
ISR_NOERR 47                    /* IRQ15 — also the 8259 spurious slot */

/* -------------------------------------------------------------------------
 * User-mode syscall gate (vector 0x80). Installed by core::SyscallInit via
 * IdtSetUserGate so the descriptor has DPL=3 — which is what makes the
 * int instruction legal from ring 3 in the first place. No error code is
 * pushed by the CPU for `int N`, so this uses the NOERR shape.
 *
 * The stub reaches isr_common just like any other ISR; the dispatcher
 * branches on frame->vector == 0x80 and routes into core::SyscallDispatch.
 * That handler may write frame->rax with a return value before returning,
 * and isr_common's pop-all + iretq delivers it to ring 3. A syscall that
 * never returns (SYS_exit) simply calls sched::SchedExit from the
 * dispatcher — the half-consumed trap frame is abandoned with its task.
 * ------------------------------------------------------------------------- */
ISR_NOERR 128                   /* int 0x80 — user-mode syscall gate */

/* -------------------------------------------------------------------------
 * Spurious-vector stubs. Cover every IDT slot from 48..127 and
 * 129..254 (skipping 128 = syscall and 255 = LAPIC spurious below).
 *
 * Without these, vectors above 47 are a zero IDT gate (Present=0)
 * which makes the CPU cascade into #NP — losing the original
 * vector number in favour of #NP's "selector that #NP'd" error
 * code. Filling the IDT means a stray INT n / IPI / spurious
 * device interrupt logs the actual vector and resumes, instead of
 * #NP-cascading into a panic.
 *
 * Uses .altmacro + .rept to emit the 206 stubs without 206 lines
 * of macro invocation. Each expansion is identical to ISR_NOERR
 * for the corresponding vector number.
 * ------------------------------------------------------------------------- */
.altmacro
.macro mkstub n
    .align 16
    .global isr_\n
isr_\n:
    endbr64
    push    0
    push    \n
    jmp     isr_common
.endm

.set i, 48
.rept 80                        /* 48..127 */
    mkstub %i
    .set i, i+1
.endr

.set i, 129
.rept 126                       /* 129..254 */
    mkstub %i
    .set i, i+1
.endr

/* -------------------------------------------------------------------------
 * LAPIC spurious-interrupt vector. Per Intel SDM, the SVR's vector field
 * has the low 4 bits hard-wired to 1, so the spurious vector is conven-
 * tionally 0xFF. Exported under both names — `isr_spurious` for the
 * historical lapic.cpp reference, `isr_255` for the IDT-fill loop's
 * `.quad isr_N` symmetry.
 * ------------------------------------------------------------------------- */
.align 16
.global isr_spurious
.global isr_255
isr_spurious:
isr_255:
    endbr64
    push    0                   /* fake error code      */
    push    0xFF                /* vector number        */
    jmp     isr_common


/* -------------------------------------------------------------------------
 * Common tail. On entry the stack already has:
 *   [top] vector, error_code, rip, cs, rflags, rsp, ss
 *
 * We push the 15 general-purpose registers in a fixed order, hand the
 * dispatcher a pointer to the frame, then iretq. Today the dispatcher
 * halts unconditionally, so the return path is fossil — but it's written
 * so that a future handler which actually recovers doesn't have to touch
 * this file.
 * ------------------------------------------------------------------------- */
.align 16
.global isr_common
isr_common:
    /* swapgs gate — restore the kernel's pcpu pointer into GSBASE if we
     * entered from user mode. On entry the stack layout (from rsp) is:
     *   vec (0), err (8), rip (16), cs (24), rflags, rsp, ss.
     * The pushed CS's low two bits encode RPL: 0 for kernel entry,
     * 3 for user entry. `test qword ptr [rsp+24], 3` is zero for
     * ring-0 entry (no swapgs — GSBASE already correct) and non-zero
     * for ring-3 entry (swapgs to retrieve the kernel pcpu pointer
     * stashed in KERNEL_GS_BASE by EnterUserMode or by the previous
     * iretq-to-user). Without this, any gs-relative read
     * (cpu::CurrentCpu() etc.) from a trap handler that came from
     * user mode would deref address 0. */
    test    qword ptr [rsp + 24], 3
    jz      1f
    swapgs
1:
    push    rax
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    push    rbp
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    /* SysV AMD64: first argument in rdi. Point it at the trap frame. */
    mov     rdi, rsp

    /* Preserve 16-byte stack alignment across the call. rsp currently has
     * 15 GPRs + vector + error = 17 * 8 = 136 bytes pushed on top of the
     * CPU's 40-byte iretq frame — total 176, which is already 16-aligned.
     * No extra sub/add rsp needed. */
    call    TrapDispatch

    /* Unreachable today (TrapDispatch halts). Kept so the return path is
     * present when some future vector actually returns. */
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rbp
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax
    add     rsp, 16             /* discard vector + error_code */

    /* Mirror of the entry gate. Stack is now: rip (0), cs (8), rflags,
     * rsp, ss. If we're returning to user mode (CS.RPL == 3), swapgs
     * to restore user's GSBASE from KERNEL_GS_BASE and stash our pcpu
     * pointer back into KERNEL_GS_BASE for the next entry. Skipped on
     * kernel-mode returns (IRQ from kernel, kernel-side faults), where
     * GSBASE is already what the resumed kernel context expects. */
    test    qword ptr [rsp + 8], 3
    jz      2f
    swapgs
2:
    iretq


/* -------------------------------------------------------------------------
 * Address table consumed by idt.cpp. One u64 per IDT vector — full
 * 256 slots so IdtInit can install every entry in a single loop.
 * Slot 128 (syscall) gets re-installed with DPL=3 by SyscallInit;
 * slot 255 (LAPIC spurious) gets re-installed by LapicInit. Both
 * overrides are full SetGate writes, so the initial DPL=0 install
 * is overwritten cleanly.
 *
 * Built via .altmacro + .rept for symmetry with the stub block
 * above. Kept in .rodata because nothing writes to it after link.
 * ------------------------------------------------------------------------- */
.section .rodata
.align 8
.altmacro
.macro stubref n
    .quad isr_\n
.endm

.global isr_stub_table
isr_stub_table:
.set i, 0
.rept 256
    stubref %i
    .set i, i+1
.endr

/* Stack is NX — silence lld's PT_GNU_STACK warning. */
.section .note.GNU-stack, "", @progbits
