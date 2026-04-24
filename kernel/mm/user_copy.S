/*
 * DuetOS — user-pointer copy primitives with fault fixup.
 *
 * The C++ helpers mm::CopyFromUser / mm::CopyToUser delegate the
 * actual byte-by-byte memory move to one of the assembly routines
 * here. Each routine is bracketed by a pair of labels:
 *
 *     __copy_user_{from,to}_start:   first potentially-faulting insn
 *     __copy_user_{from,to}_end:     one past the last such insn
 *
 * The trap dispatcher (kernel/arch/x86_64/traps.cpp) inspects the
 * saved RIP on a ring-0 #PF. If the RIP falls inside one of these
 * [start, end) ranges, the fault is recoverable: the dispatcher
 * overwrites frame->rip with __copy_user_fault_fixup and iretq's.
 * Control resumes at the fixup, which:
 *
 *   - issues `clac` so SMAP returns to its default posture, and
 *   - returns `false` (rax = 0) to the C++ caller.
 *
 * This lets the kernel survive a user page vanishing mid-copy —
 * a race possible under SMP user-mode or demand paging — without
 * panicking. Same mechanism used by Linux's `_ASM_EXTABLE`, but
 * range-based instead of per-instruction (finer granularity isn't
 * needed since either ALL bytes in the loop are at-risk, or none).
 *
 * Calling convention (SysV AMD64):
 *   rdi = kernel dst / user dst
 *   rsi = user src   / kernel src
 *   rdx = byte count
 * Returns: rax = 1 on success, 0 on recovered fault.
 *
 * SMAP gating: each routine issues stac on entry and clac on exit
 * (both success and failure paths), so the byte loop's `rep movsb`
 * runs with RFLAGS.AC=1 and no other ring-0 code accidentally
 * inherits that state on the way out.
 */

.intel_syntax noprefix

.section .text
.align 16

/* -------------------------------------------------------------------------
 * bool _copy_user_from(void* kernel_dst, const void* user_src, u64 len);
 *
 * Copies `len` bytes from user-space source into kernel-space
 * destination. Returns 1 if every byte copied; 0 if the loop
 * faulted (some prefix may have been copied).
 * ------------------------------------------------------------------------- */
.global _copy_user_from
.type _copy_user_from, @function
_copy_user_from:
    endbr64

    /* Success-return baseline. The fixup path overwrites this on
     * the way out. */
    mov     eax, 1

    stac                            /* allow kernel to read user pages */

.global __copy_user_from_start
__copy_user_from_start:
    /* Byte-at-a-time copy. rep movsb would be faster on modern CPUs
     * but the fault fixup needs rip-inside-range semantics that
     * survive microcoded instructions — plain mov/inc/dec is
     * unambiguous. mov al, [rsi] is the faulting instruction; if
     * the user page is gone, the trap dispatcher picks us up. */
1:
    test    rdx, rdx
    jz      2f
    mov     cl, byte ptr [rsi]
    mov     byte ptr [rdi], cl
    inc     rsi
    inc     rdi
    dec     rdx
    jmp     1b
2:
.global __copy_user_from_end
__copy_user_from_end:

    clac
    ret
.size _copy_user_from, . - _copy_user_from


/* -------------------------------------------------------------------------
 * bool _copy_user_to(void* user_dst, const void* kernel_src, u64 len);
 * Symmetric to _copy_user_from; the user side is the DESTINATION.
 * ------------------------------------------------------------------------- */
.align 16
.global _copy_user_to
.type _copy_user_to, @function
_copy_user_to:
    endbr64

    mov     eax, 1
    stac

.global __copy_user_to_start
__copy_user_to_start:
1:
    test    rdx, rdx
    jz      2f
    mov     cl, byte ptr [rsi]
    mov     byte ptr [rdi], cl
    inc     rsi
    inc     rdi
    dec     rdx
    jmp     1b
2:
.global __copy_user_to_end
__copy_user_to_end:

    clac
    ret
.size _copy_user_to, . - _copy_user_to


/* -------------------------------------------------------------------------
 * Fault fixup landing pad. The trap dispatcher rewrites frame->rip
 * to point here when a #PF fires inside either of the [start, end)
 * ranges above. On entry rip = this label, rax = undefined, RFLAGS.AC
 * may be 1 (the copy loop was inside the SMAP window).
 *
 * We clac unconditionally so we return to the caller with AC cleared,
 * then zero rax to signal "not all bytes copied" and ret.
 * ------------------------------------------------------------------------- */
.align 16
.global __copy_user_fault_fixup
.type __copy_user_fault_fixup, @function
__copy_user_fault_fixup:
    endbr64
    clac
    xor     eax, eax
    ret
.size __copy_user_fault_fixup, . - __copy_user_fault_fixup


/* NX stack — silence lld's PT_GNU_STACK warning. */
.section .note.GNU-stack, "", @progbits
