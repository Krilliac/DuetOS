/*
 * DuetOS — retpoline thunks.
 *
 * -mretpoline replaces every `jmp/call *%rXX` the compiler would
 * emit with `call __x86_indirect_thunk_rXX`. These thunks are the
 * safe-speculation alternative: they trap speculation at `lfence`
 * then return via `ret` to the intended target. Attackers who can
 * poison the BTB can't use an indirect branch to speculate into
 * a gadget — lfence stops the speculative run and the ret's
 * prediction comes off the (trusted) return-stack-buffer instead
 * of the (poisoned) BTB.
 *
 * Shape (for each of rax, rbx, rcx, rdx, rsi, rdi, rbp, r8..r15):
 *
 *   __x86_indirect_thunk_rXX:
 *       call    LAUNCH          ; push current rip onto stack
 *   capture:
 *       pause                   ; spin tightly; speculation ends up here
 *       lfence                  ;   instead of the real target
 *       jmp     capture
 *   LAUNCH:
 *       mov     [rsp], rXX      ; overwrite saved rip with the target
 *       ret                     ; RSB-predicted return to rXX
 *
 * This is the standard Linux / Chromium retpoline shape. Each
 * thunk is at most a few dozen bytes; there are 15 thunks so
 * total overhead is < 1 KiB of .text.
 *
 * Only emit thunks the compiler actually calls. Linker gc-sections
 * drops unused ones, so defining all 15 is safe.
 */

.intel_syntax noprefix

.section .text
.align 16

.macro RETPOLINE_THUNK reg
    .global __x86_indirect_thunk_\reg
    .type __x86_indirect_thunk_\reg, @function
    .align 16
__x86_indirect_thunk_\reg:
    endbr64
    call    2f
1:
    pause
    lfence
    jmp     1b
2:
    mov     [rsp], \reg
    ret
    .size __x86_indirect_thunk_\reg, . - __x86_indirect_thunk_\reg
.endm

RETPOLINE_THUNK rax
RETPOLINE_THUNK rbx
RETPOLINE_THUNK rcx
RETPOLINE_THUNK rdx
RETPOLINE_THUNK rsi
RETPOLINE_THUNK rdi
RETPOLINE_THUNK rbp
RETPOLINE_THUNK r8
RETPOLINE_THUNK r9
RETPOLINE_THUNK r10
RETPOLINE_THUNK r11
RETPOLINE_THUNK r12
RETPOLINE_THUNK r13
RETPOLINE_THUNK r14
RETPOLINE_THUNK r15

/*
 * __llvm_retpoline_r11 — diagnostic override for clang's auto-emitted
 * retpoline thunk. The compiler emits `call __llvm_retpoline_r11` for
 * every `call *%r11` shape (which, post -mretpoline, is almost every
 * indirect call in the kernel: function-pointer fields, vtables,
 * lambda captures, retpoline-mediated tail-calls). By providing a
 * strong definition here we intercept ALL such dispatches and
 * validate the target before transferring control.
 *
 * Validates r11 ∈ [_text_start, _text_end). On a wild value, raw-
 * SerialWrite a `[retpoline] WILD ...` line + tail-call into the C
 * panic helper RetpolineWildCallback. On a clean value, fall through
 * to the standard retpoline body (mirror of __x86_indirect_thunk_r11
 * above) so the indirect call retains its Spectre v2 mitigation.
 *
 * Observed 2026-05-22: ~1/10 SMP=8 boots hit a fresh AP idle's first
 * IRQ-handler dispatch with r11 = lockdep/rcu g_per_cpu .bss address
 * (NX page → #PF NX_VIOLATION) — without this gate the panic banner
 * named the wild RIP, not the calling site or the corrupt loader.
 * Targeted, ArmedLog-style: a clean boot stays quiet, a regression
 * emits ONE sentinel line + halts cleanly.
 */
.global __llvm_retpoline_r11
.type __llvm_retpoline_r11, @function
.align 16
__llvm_retpoline_r11:
    endbr64
    /* Range-check r11 against [_text_start, _text_end). lo and hi
     * are loaded with the absolute symbol addresses; lld resolves
     * them at link time. We use scratch reg rax + rcx (both
     * caller-saved by SysV — clobbered by the impending indirect
     * call anyway). */
    push    rax
    push    rcx
    movabs  rax, offset _text_start
    movabs  rcx, offset _text_end
    cmp     r11, rax
    jb      .Lretpoline_wild
    cmp     r11, rcx
    jae     .Lretpoline_wild
    pop     rcx
    pop     rax
    /* Standard retpoline body — speculation trap + safe ret. */
    call    .Lretpoline_launch_r11
.Lretpoline_capture_r11:
    pause
    lfence
    jmp     .Lretpoline_capture_r11
.Lretpoline_launch_r11:
    mov     [rsp], r11
    ret
.Lretpoline_wild:
    /* Restore stack from the cmp pushes so RetpolineWildCallback
     * sees a stack pointer matching the original indirect-call
     * site's frame. rax/rcx values don't matter — they're caller-
     * saved and the callee never returns anyway. */
    pop     rcx
    pop     rax
    mov     rdi, r11
    call    RetpolineWildCallback
    /* Belt-and-braces — RetpolineWildCallback is [[noreturn]]. */
    cli
    hlt
    .size __llvm_retpoline_r11, . - __llvm_retpoline_r11

/* NX stack — silence lld's PT_GNU_STACK warning. */
.section .note.GNU-stack, "", @progbits
