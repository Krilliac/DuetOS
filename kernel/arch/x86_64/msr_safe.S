/*
 * DuetOS — Fault-recoverable wrmsr / rdmsr.
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
 * `ReadMsrSafeRaw(msr, u64* out) -> bool` is the mirror image, with
 * its own label triple (rdmsr_safe_start / _end / _fault). Callers
 * use the `arch::ReadMsrSafe` wrapper in msr_safe.cpp rather than
 * this symbol directly; the wrapper refuses to issue the rdmsr
 * until the extable row is actually registered, so a caller that
 * runs too early in boot gets `false` instead of an unrecoverable
 * #GP. (That is not hypothetical: the cpufreq self-test hit exactly
 * that ordering under KVM.) It is the primitive that lets a caller
 * PROBE an MSR instead of predicting whether the part implements
 * it: every MSR consumer in the tree used to defend with a static
 * vendor + hypervisor gate
 * precisely because a bad `rdmsr` was unrecoverable. On the fault
 * path `*out` is left untouched and the function returns 0.
 *
 * SysV x86-64 ABI:
 *   rdi = u32   msr address
 *   rsi = u64*  destination (must be non-null; the store is
 *               OUTSIDE the protected range on purpose, so a bad
 *               pointer is a real kernel bug and faults loudly)
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

.align 16
.global ReadMsrSafeRaw
.type ReadMsrSafeRaw, @function
ReadMsrSafeRaw:
    endbr64
    /* rcx = MSR selector. rdmsr returns edx:eax; zero both first so
       a fault leaves no stale register state for a debugger to
       misread. rsi (the out pointer) is callee-visible and rdmsr
       does not clobber it. */
    mov     rcx, rdi
    xor     eax, eax
    xor     edx, edx

    .global rdmsr_safe_start
rdmsr_safe_start:
    rdmsr
    .global rdmsr_safe_end
rdmsr_safe_end:
    shl     rdx, 32
    or      rax, rdx
    mov     [rsi], rax
    mov     eax, 1
    ret

    .global rdmsr_safe_fault
rdmsr_safe_fault:
    xor     eax, eax
    ret
.size ReadMsrSafeRaw, . - ReadMsrSafeRaw
