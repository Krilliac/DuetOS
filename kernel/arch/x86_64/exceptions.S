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
    push    0                   /* fake error code      */
    push    \vec                /* vector number        */
    jmp     isr_common
.endm

.macro ISR_ERR vec
    .align 16
    .global isr_\vec
isr_\vec:
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
 * LAPIC spurious-interrupt vector. Per Intel SDM, the SVR's vector field
 * has the low 4 bits hard-wired to 1, so the spurious vector is conven-
 * tionally 0xFF. Exported by name so the LAPIC bring-up can install it
 * directly without extending isr_stub_table to 256 entries.
 * ------------------------------------------------------------------------- */
.align 16
.global isr_spurious
isr_spurious:
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
    iretq


/* -------------------------------------------------------------------------
 * Address table consumed by idt.cpp. One u64 per exception vector,
 * pointing at the corresponding stub. Kept in .rodata because nothing
 * writes to it after link.
 * ------------------------------------------------------------------------- */
.section .rodata
.align 8
.global isr_stub_table
isr_stub_table:
    .quad   isr_0
    .quad   isr_1
    .quad   isr_2
    .quad   isr_3
    .quad   isr_4
    .quad   isr_5
    .quad   isr_6
    .quad   isr_7
    .quad   isr_8
    .quad   isr_9
    .quad   isr_10
    .quad   isr_11
    .quad   isr_12
    .quad   isr_13
    .quad   isr_14
    .quad   isr_15
    .quad   isr_16
    .quad   isr_17
    .quad   isr_18
    .quad   isr_19
    .quad   isr_20
    .quad   isr_21
    .quad   isr_22
    .quad   isr_23
    .quad   isr_24
    .quad   isr_25
    .quad   isr_26
    .quad   isr_27
    .quad   isr_28
    .quad   isr_29
    .quad   isr_30
    .quad   isr_31
    .quad   isr_32
    .quad   isr_33
    .quad   isr_34
    .quad   isr_35
    .quad   isr_36
    .quad   isr_37
    .quad   isr_38
    .quad   isr_39
    .quad   isr_40
    .quad   isr_41
    .quad   isr_42
    .quad   isr_43
    .quad   isr_44
    .quad   isr_45
    .quad   isr_46
    .quad   isr_47

/* Stack is NX — silence lld's PT_GNU_STACK warning. */
.section .note.GNU-stack, "", @progbits
