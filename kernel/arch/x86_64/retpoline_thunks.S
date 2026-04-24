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

/* NX stack — silence lld's PT_GNU_STACK warning. */
.section .note.GNU-stack, "", @progbits
