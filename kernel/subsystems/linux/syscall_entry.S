/*
 * CustomOS — Linux-ABI syscall entry stub.
 *
 * Target of MSR_LSTAR. Entered by the `syscall` instruction from
 * ring 3 in a task whose Process::abi_flavor is kAbiLinux. On
 * entry:
 *   - CS/SS have been swapped to kernel selectors.
 *   - RFLAGS has been saved to R11 (with SFMASK bits cleared).
 *   - User RIP has been saved to RCX.
 *   - All other GP registers carry user values.
 *   - RSP is still the user RSP. SS is kernel-data already.
 *
 * We cannot `sysret` to return on CustomOS: its GDT places user
 * code and user data in an order incompatible with SYSRET's
 * STAR[63:48] + {8,16} selector arithmetic. We use `iretq`
 * instead — which works with any GDT as long as the iret frame
 * on the stack is well-formed.
 *
 * TrapFrame layout consumed by the C dispatcher (kernel/arch/
 * x86_64/traps.h): from low to high address:
 *   r15, r14, r13, r12, r11, r10, r9, r8,
 *   rbp, rdi, rsi, rdx, rcx, rbx, rax,
 *   vector, error_code,
 *   rip, cs, rflags, rsp, ss
 * — identical to the int-0x80 path so LinuxSyscallDispatch can
 * reuse the TrapFrame shape.
 */

.intel_syntax noprefix

/* Selectors — keep in sync with arch/x86_64/gdt.h. */
.set KERNEL_DS, 0x10
.set USER_CS,   0x2B
.set USER_DS,   0x33

/* PerCpu offsets — keep in sync with cpu/percpu.h's
 * kPerCpuKernelRsp / kPerCpuUserRspScratch constants. */
.set PERCPU_KERNEL_RSP,       32
.set PERCPU_USER_RSP_SCRATCH, 40

.section .text
.align 16
.global linux_syscall_entry
linux_syscall_entry:
    /* Swap to kernel GS so we can reach PerCpu. CPU entered with
     * user GS still loaded. */
    swapgs

    /* Save user RSP into per-CPU scratch; load kernel RSP. */
    mov gs:[PERCPU_USER_RSP_SCRATCH], rsp
    mov rsp, gs:[PERCPU_KERNEL_RSP]

    /* Build the CPU portion of a TrapFrame (ss, rsp, rflags, cs,
     * rip) in the order the dispatcher + iretq expect. */
    push    USER_DS
    push    gs:[PERCPU_USER_RSP_SCRATCH]
    push    r11                         /* user rflags */
    push    USER_CS
    push    rcx                         /* user rip */

    /* Per-vector stub portion: fake error_code + vector marker.
     * vector = 0x80 so any debug tooling that inspects frames
     * sees the same "syscall-y" tag the int-0x80 path uses. */
    push    0                           /* error_code */
    push    0x80                        /* vector */

    /* GP registers in the TrapFrame order. */
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

    /* Pass TrapFrame* to the C dispatcher. cld per SysV ABI. */
    mov     rdi, rsp
    cld
    call    LinuxSyscallDispatch

    /* If the dispatcher returned (i.e. did NOT call SchedExit
     * or similar), frame->rax now carries the syscall's return
     * value. Pop the TrapFrame back into registers, then iretq. */
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
    add     rsp, 16                     /* skip vector + error_code */

    /* Restore user GS right before iretq. */
    swapgs
    iretq

.size linux_syscall_entry, . - linux_syscall_entry

/* The stack this code grows is a normal kernel stack — no
 * execute-from-it scenario — but being explicit about
 * no-exec-stack keeps ELF linker warnings quiet on hosts
 * that check it. */
.section .note.GNU-stack, "", @progbits
