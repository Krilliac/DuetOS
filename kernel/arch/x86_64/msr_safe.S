/*
 * DuetOS — Fault-recoverable wrmsr.
 *
 * `WriteMsrSafe(msr, value) -> bool` runs a single `wrmsr` between
 * three exported labels:
 *
 *   wrmsr_safe_start  — the `wrmsr` instruction itself
 *   wrmsr_safe_end    — one past `wrmsr` (success continuation)
 *   wrmsr_safe_fault  — fixup target the trap dispatcher steers to
 *                       on #GP / #PF within [start, end)
 *
 * The trap dispatcher (`kernel/arch/x86_64/traps.cpp`) walks the
 * kernel extable on every ring-0 #GP / #PF; an extable entry that
 * covers the wrmsr instruction redirects `frame->rip` to the
 * fixup, which returns 0 to the caller. Registration of the row
 * is done at boot (see `RegisterMsrSafeExtable()` in
 * `kernel/arch/x86_64/msr_safe.cpp`).
 *
 * Why this exists: the BSP-side LAPIC IPI path (LapicSendIcr →
 * arch::WriteMsr(0x830, ...)) #GPs intermittently on KVM-accel
 * QEMU runs (≈20% of debug-preset boots). The original wrmsr
 * faults, the trap dispatcher's PanicBroadcastNmi() retries the
 * same wrmsr, and the recursive-fault detector halts the BSP —
 * the kernel hangs without a panic dump. Routing the LAPIC IPI
 * wrmsr through this safe wrapper lets the kernel keep running:
 * the IPI is silently lost (the destination AP doesn't start /
 * the reschedule is delayed one tick), but no recursive halt.
 *
 * SysV x86-64 ABI:
 *   rdi = u32   msr address
 *   rsi = u64   value
 *   ret eax = 1 on success, 0 on #GP
 *
 * Endbr64 prologue: present so the indirect call from C++
 * resolves cleanly once CET-IBT is enabled (mirrors cet_asm.S).
 */

.intel_syntax noprefix

.section .text

.align 16
.global WriteMsrSafe
.type WriteMsrSafe, @function
WriteMsrSafe:
    endbr64
    /* Load wrmsr operands. rax = low 32, rdx = high 32, rcx = MSR. */
    mov     rcx, rdi
    mov     rax, rsi
    mov     rdx, rsi
    shr     rdx, 32

    .global wrmsr_safe_start
wrmsr_safe_start:
    wrmsr
    .global wrmsr_safe_end
wrmsr_safe_end:
    mov     eax, 1
    ret

    .global wrmsr_safe_fault
wrmsr_safe_fault:
    xor     eax, eax
    ret
.size WriteMsrSafe, . - WriteMsrSafe
