/*
 * DuetOS — Win32 NT-style `int 0x2E` syscall entry.
 *
 * Mirror of the int-0x80 entry but tagged with vector 0x2E so the
 * dispatcher routes to the NT translation table instead of the
 * native dispatcher. ntdll built by DuetOS issues `int 0x80` with
 * DuetOS-native syscall numbers and so never reaches this stub;
 * the stub exists for unmodified third-party binaries (real
 * Windows ntdll, malware corpora, the WINE test suite) that issue
 * the legacy NT gate.
 *
 * Today the IDT does NOT install vector 0x2E (idt.cpp installs
 * isr_46 there as a generic spurious-vector stub). Wiring this
 * stub in is a separate slice — set the IDT entry's offset to
 * `nt_syscall_entry` instead of `isr_46`, with DPL=3 so user-mode
 * `int 0x2E` is legal.
 *
 * Frame shape: identical to int-0x80 (and to the Linux SYSCALL
 * fast path), so `NtSyscallEntryDispatch` can introspect the same
 * `arch::TrapFrame` the other dispatchers consume.
 */

.intel_syntax noprefix

.section .text
.align 16
.global nt_syscall_entry
nt_syscall_entry:
    endbr64

    /* `int N` from ring 3 already triggered the CPU's DPL=3 gate
     * dance: stack swap to TSS.RSP0, push of SS, RSP, RFLAGS, CS,
     * RIP. No error code is pushed for software interrupts. */
    push    0                   /* fake error_code */
    push    0x2E                /* vector marker */

    /* Same swapgs gate as isr_common: ring-3 entry needs swapgs
     * to recover the kernel's per-CPU pointer. RPL test on the
     * pushed CS at [rsp+24] (vec, err, rip, cs). */
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

    mov     rdi, rsp
    cld
    call    NtSyscallEntryDispatch

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
    add     rsp, 16             /* discard vec + err */

    test    qword ptr [rsp + 8], 3
    jz      2f
    swapgs
2:
    iretq

.size nt_syscall_entry, . - nt_syscall_entry

.section .note.GNU-stack, "", @progbits
