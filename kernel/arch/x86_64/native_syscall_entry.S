/*
 * DuetOS — native-ABI syscall entry stub.
 *
 * Counterpart of kernel/subsystems/linux/syscall_entry.S. Same shape:
 * the stub is the target of MSR_LSTAR for tasks whose
 * `Process::abi_flavor` is the native DuetOS ABI. It builds a
 * TrapFrame in the layout `arch::TrapFrame` describes, hands it to
 * `NativeSyscallEntry` (a small extern "C" shim that forwards to
 * `duetos::core::SyscallDispatch`), and returns to user mode via
 * `iretq`.
 *
 * We could re-use `linux_syscall_entry` and branch on a per-CPU
 * "current ABI" cell inside the entry; that would buy a single LSTAR
 * write at boot. The trade-off is a runtime test on every syscall.
 * Splitting the stub keeps each entry path single-purpose and lets
 * the LSTAR target be retargeted on context switch (one wrmsr per
 * switch, ~80 cycles) only on switches that cross an ABI boundary.
 *
 * Selectors and per-CPU offsets are kept in sync with
 * subsystems/linux/syscall_entry.S — both stubs read kernel_rsp /
 * user_rsp_scratch from the same fixed PerCpu offsets, and both
 * iretq to user mode through the GDT entries the SyscallInit
 * MSR_STAR write established.
 */

.intel_syntax noprefix

.set KERNEL_DS, 0x10
.set USER_CS,   0x2B
.set USER_DS,   0x33

.set PERCPU_KERNEL_RSP,       32
.set PERCPU_USER_RSP_SCRATCH, 40

.section .text
.align 16
.global native_syscall_entry
native_syscall_entry:
    /* Reach the kernel's per-CPU pointer. CPU entered with user GS
     * loaded; swapgs swaps in the kernel pcpu pointer that
     * KERNEL_GS_BASE held. */
    swapgs

    /* Stash user RSP, switch to this CPU's kernel RSP. */
    mov gs:[PERCPU_USER_RSP_SCRATCH], rsp
    mov rsp, gs:[PERCPU_KERNEL_RSP]

    /* Build the iretq portion of the TrapFrame. iretq pops in this
     * order from low to high address: rip, cs, rflags, rsp, ss. We
     * push them in reverse so the resulting layout matches. */
    push    USER_DS
    push    gs:[PERCPU_USER_RSP_SCRATCH]
    push    r11                         /* user rflags (CPU saved) */
    push    USER_CS
    push    rcx                         /* user rip (CPU saved) */

    /* Per-vector portion: error_code = 0, vector = 0x80 so any
     * trace tooling that introspects the frame sees the same tag
     * the int-0x80 path uses. */
    push    0
    push    0x80

    /* GP registers in the TrapFrame order. Mirrors exceptions.S
     * isr_common's GPR push sequence. */
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

    /* SysV ABI: TrapFrame* in rdi. cld per ABI before any C call. */
    mov     rdi, rsp
    cld
    call    NativeSyscallEntry

    /* Frame->rax now carries the return value (or the syscall is
     * one that never returns and SchedExit was called from inside
     * the dispatcher). Pop the frame and iretq back to user. */
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
    add     rsp, 16                     /* discard vector + error_code */

    /* Restore user GS right before iretq. */
    swapgs
    iretq

.size native_syscall_entry, . - native_syscall_entry

.section .note.GNU-stack, "", @progbits
