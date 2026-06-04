/*
 * DuetOS — CPU exception stubs for vectors 0..31.
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
 * In a DuetOS system the legacy 8259 PIC is masked (see pic.cpp); these
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

    /* --- DIAG (boot-tail wild-frame chase, 2026-06-04): record this trap's
     * entry shape into the fixed BSS ring (traps.cpp g_trap_ring) so a later
     * wild-frame panic can show the trap sequence that produced it. rax..rdx
     * are saved on the stack above and restored by the IRQ-return pop-all, so
     * they are free scratch here; the 32-bit remap below and the C dispatcher
     * read only stack slots, never live rax..rdx. Offsets from rsp after the
     * 15 pushes: [rsp+120]=vector, [rsp+136]=saved rip, [rsp+160]=pre-trap rsp.
     * Single-CPU diagnostic (the bug is single-CPU VBox); the non-atomic idx
     * bump is acceptable. */
    movabs  rcx, offset g_trap_ring_idx
    mov     rax, [rcx]              /* idx */
    mov     rbx, rax
    and     rbx, 0xF               /* idx & 15 */
    shl     rbx, 5                 /* * 32 bytes/slot */
    movabs  rdx, offset g_trap_ring
    add     rdx, rbx               /* &g_trap_ring[idx & 15] */
    mov     rbx, [rsp + 120]       /* vector */
    mov     [rdx + 0], rbx
    mov     rbx, [rsp + 136]       /* saved rip */
    mov     [rdx + 8], rbx
    mov     rbx, [rsp + 160]       /* pre-trap rsp (CPU iretq frame) */
    mov     [rdx + 16], rbx
    mov     [rdx + 24], rsp        /* frame ptr handed to TrapDispatch */
    inc     rax
    mov     [rcx], rax             /* idx++ */
    /* --- end DIAG --- */

    /* 32-bit syscall ABI remap. Trap frame layout after the 15 pushes:
     *   [rsp+0]    r15
     *   [rsp+8]    r14
     *   [rsp+16]   r13
     *   [rsp+24]   r12
     *   [rsp+32]   r11
     *   [rsp+40]   r10
     *   [rsp+48]   r9
     *   [rsp+56]   r8
     *   [rsp+64]   rbp
     *   [rsp+72]   rdi   (target arg1)
     *   [rsp+80]   rsi   (target arg2)
     *   [rsp+88]   rdx   (target arg3 / source arg3 — same slot)
     *   [rsp+96]   rcx   (source arg2)
     *   [rsp+104]  rbx   (source arg1)
     *   [rsp+112]  rax   (syscall number, kept)
     *   [rsp+120]  vector
     *   [rsp+128]  error
     *   [rsp+136]  rip
     *   [rsp+144]  cs
     *   ...
     *
     * 32-bit ABI (Linux i386, the convention we use): eax=nr,
     * ebx=a1, ecx=a2, edx=a3, esi=a4, edi=a5, ebp=a6.
     * 64-bit ABI (what the C++ dispatcher expects): rax=nr,
     * rdi=a1, rsi=a2, rdx=a3, r10=a4, r8=a5, r9=a6.
     *
     * If CS == 0x3B (kUserCode32Selector) the caller is a 32-bit
     * compat-mode PE and the arg slots need to be moved into the
     * 64-bit slots before TrapDispatch reads them. Source-stable
     * order: snapshot every source via a kernel scratch register
     * BEFORE writing any target slot. */
    cmp     word ptr [rsp + 144], 0x3B
    jne     90f
    mov     r11, [rsp + 104]    /* source: rbx (arg1) */
    mov     r12, [rsp + 96]     /* source: rcx (arg2) */
    mov     r13, [rsp + 80]     /* source: rsi (arg4) */
    mov     r14, [rsp + 72]     /* source: rdi (arg5) */
    mov     r15, [rsp + 64]     /* source: rbp (arg6) */
    mov     [rsp + 72],  r11    /* target rdi := arg1 */
    mov     [rsp + 80],  r12    /* target rsi := arg2 */
    mov     [rsp + 40],  r13    /* target r10 := arg4 */
    mov     [rsp + 56],  r14    /* target r8  := arg5 */
    mov     [rsp + 48],  r15    /* target r9  := arg6 */
    /* rdx (arg3) and rax (syscall_no) are already where the
     * C++ dispatcher expects them. The CPU zero-extended every
     * 32-bit register write on the user side, so the slots
     * holding 32-bit user pointers already contain a clean
     * 64-bit value (high 32 == 0). */
90:

    /* SysV AMD64: first argument in rdi. Point it at the trap frame. */
    mov     rdi, rsp

    /* Preserve 16-byte stack alignment across the call. rsp currently has
     * 15 GPRs + vector + error = 17 * 8 = 136 bytes pushed on top of the
     * CPU's 40-byte iretq frame — total 176, which is already 16-aligned.
     * No extra sub/add rsp needed. */
    call    TrapDispatch

    /* 32-bit syscall ABI un-remap. The remap above clobbered the
     * trap frame's rdi (slot 72) and rsi (slot 80) slots with the
     * remapped arg1 / arg2 values. iretq pops those slots back to
     * the user's rdi/rsi — but in compat mode the user expects
     * their pre-syscall edi/esi values to be preserved (32-bit
     * syscalls don't return in those regs). The remap also wrote
     * source rsi/rdi into target r10 (slot 40) and target r8
     * (slot 56); the C++ syscall handlers never write back to arg
     * slots, so those still hold the user's original rsi/rdi
     * values. Copy them back to the rsi/rdi slots before the
     * pop-all. Kernel32_32!WriteFile's `*lpWritten = bytes_written`
     * needs esi intact to find the caller's DWORD; without this
     * restore, esi was clobbered with the rcx_user value during
     * the remap and the store at 0x10021111 page-faulted. */
    cmp     word ptr [rsp + 144], 0x3B
    jne     91f
    mov     r11, [rsp + 40]     /* target r10 still = user's orig rsi */
    mov     r12, [rsp + 56]     /* target r8  still = user's orig rdi */
    mov     [rsp + 80], r11     /* restore rsi slot */
    mov     [rsp + 72], r12     /* restore rdi slot */
91:

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
    /* Iretq-frame RIP validator (kernel-mode return only). For a
     * ring-0 → ring-0 return, the popped RIP must be inside kernel
     * `.text` or the CPU will execute random .bss / .data bytes —
     * what we caught as `#PF NX_VIOLATION at rip=0xffffffff8132axxx`
     * in the lockdep g_per_cpu region during boot-tail SMP=8 sweeps.
     * The per-call validators (sched/trampoline, sync/rcu DrainQueue,
     * arch/traps IrqHandler, __llvm_retpoline_r11) all stay silent
     * because the wild value never went through them — the trap-
     * frame's saved RIP was scribbled while the C handler was
     * running and the unconditional iretq below loaded it. Catching
     * here names the offender (current trap-frame snapshot, rip)
     * and halts before the silent control transfer.
     *
     * Ring-3 returns are skipped: a user-mode RIP is anywhere in
     * the process VA range. The kernel doesn't bound those.
     *
     * rax + rcx are clobbered by the cmp, but iretq pops a fresh
     * register file from [rsp..rsp+24] (or +40 cross-ring); the
     * GPRs we touch here aren't part of that frame.
     */
    test    qword ptr [rsp + 8], 3
    jnz     3f                  /* user-mode return — skip the gate */
    push    rax
    push    rcx
    movabs  rax, offset _text_start
    movabs  rcx, offset _text_end
    cmp     qword ptr [rsp + 16], rax  /* [rsp+0]/+8 are our pushes; iretq RIP at +16 now */
    jb      .Liretq_wild
    cmp     qword ptr [rsp + 16], rcx
    jae     .Liretq_wild
    pop     rcx
    pop     rax
3:
    iretq

.Liretq_wild:
    /* Pass the wild RIP (the iretq target) to a C helper for the
     * panic banner. The helper does NOT return. Restore the pushed
     * rax/rcx so the helper sees a clean stack — but rdi/rsi (the
     * SysV arg regs) need the wild RIP; load before restoring. */
    mov     rdi, qword ptr [rsp + 16]
    pop     rcx
    pop     rax
    call    IretqFrameWildCallback
    cli
    hlt


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
