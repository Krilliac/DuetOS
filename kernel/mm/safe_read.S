/*
 * kernel/mm/safe_read.S
 *
 * Read up to N bytes from an arbitrary kernel VA into a caller-
 * provided buffer, surviving a #PF on the source. Built on the
 * same extable mechanism as user_copy.S: the load instruction
 * lives inside a bracketed [start, end) range registered with
 * the trap dispatcher. On a fault, the dispatcher rewrites
 * frame->rip to the fixup landing pad, which returns 0
 * (caller's `false`) to the C++ wrapper.
 *
 * Use cases:
 *   - panic dump's DumpInstructionBytes for addresses outside
 *     the kernel range (a user-mode VA in the active address
 *     space, a kernel VA in an unmapped guard page, ...).
 *   - debug/inspect probes that want to read a suspicious
 *     pointer without taking the whole kernel down on a stale
 *     dereference.
 *
 * NOT for user-mode reads — those still go through
 * mm::CopyFromUser, which gates on SMAP and runs in the user
 * address space context. SafeReadKernel runs in the current
 * (kernel) AS view; if the VA isn't mapped there, it faults
 * and we return false.
 *
 * Calling convention (SysV AMD64):
 *   rdi = src kernel VA
 *   rsi = dst kernel buffer
 *   rdx = byte count
 * Returns: rax = 1 on success, 0 on recovered fault.
 *
 * No SMAP gating — kernel-to-kernel.
 */

.intel_syntax noprefix

.section .text
.align 16

.global SafeReadKernelBytes
.type SafeReadKernelBytes, @function
SafeReadKernelBytes:
    endbr64
    /* movsb expects rsi=src, rdi=dst — swap from our SysV regs. */
    mov     rax, rsi                /* save dst pointer */
    mov     rsi, rdi                /* rsi = src */
    mov     rdi, rax                /* rdi = dst */
    mov     rcx, rdx                /* rcx = byte count */
.global __safe_read_kernel_start
__safe_read_kernel_start:
    rep movsb
.global __safe_read_kernel_end
__safe_read_kernel_end:
    mov     eax, 1
    ret
.size SafeReadKernelBytes, . - SafeReadKernelBytes

/* Fault fixup. The trap dispatcher iretq's here when a #PF
 * fires inside [__safe_read_kernel_start, __safe_read_kernel_end).
 * RFLAGS.AC unchanged (no SMAP window). Just zero rax and ret. */
.align 16
.global __safe_read_kernel_fault_fixup
.type __safe_read_kernel_fault_fixup, @function
__safe_read_kernel_fault_fixup:
    endbr64
    xor     eax, eax
    ret
.size __safe_read_kernel_fault_fixup, . - __safe_read_kernel_fault_fixup

/* NX stack — silence lld's PT_GNU_STACK warning. */
.section .note.GNU-stack, "", @progbits
