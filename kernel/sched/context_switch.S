/*
 * CustomOS — kernel thread context switch.
 *
 *   void ContextSwitch(u64* old_rsp_slot, u64 new_rsp);
 *
 * Saves the callee-saved general-purpose registers on the current stack,
 * stores the resulting rsp in `*old_rsp_slot`, loads `new_rsp`, restores
 * the counterpart registers from the new stack, and `ret`s. The return
 * target is whatever address sits on top of the new stack — for a fresh
 * task that's the entry function prepared by SchedCreate; for a task that
 * was previously switched out, it's the address inside Schedule() where
 * its previous context-switch call was about to return.
 *
 * SysV AMD64 calling convention: rdi = old_rsp_slot, rsi = new_rsp.
 * Callee-saved GPRs: rbx, rbp, r12..r15. Everything else is caller-saved
 * and already preserved by the C++ compiler around the call site.
 *
 * Interrupt state: this routine does NOT touch RFLAGS.IF. Callers run
 * with interrupts disabled (IRQ handler context, or explicitly via the
 * C++ wrapper around SchedYield).
 */

.intel_syntax noprefix

.section .text
.align 16
.global ContextSwitch
.type ContextSwitch, @function
ContextSwitch:
    /* ContextSwitch is called via direct `call` from sched.cpp, so
     * strictly speaking IBT doesn't require an endbr here. But marking
     * function entries is standard hygiene; emit one so a future
     * indirect caller (fn-pointer-dispatched scheduler variant) doesn't
     * need to remember to land on an endbr. Zero-cost on pre-CET CPUs. */
    endbr64
    /* Save callee-saved GPRs in a fixed order so the "fresh task" stack
     * layout in SchedCreate matches exactly. */
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15

    /* Stash the current stack pointer into *old_rsp_slot. */
    mov     [rdi], rsp

    /* Adopt the new stack. */
    mov     rsp, rsi

    /* Pop in reverse order. */
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx

    /* The top of the stack now holds either:
     *   - the return address of some previous ContextSwitch call on this
     *     task's stack, so we resume mid-Schedule() / mid-SchedYield(); or
     *   - the entry-function address planted by SchedCreate, plus one
     *     quad of alignment padding above it. Either way, ret does the
     *     right thing. */
    ret

.size ContextSwitch, . - ContextSwitch


/* -------------------------------------------------------------------------
 * SchedTaskTrampoline — the address popped by the first `ret` out of
 * ContextSwitch for a freshly-created task. SchedCreate plants the entry
 * function in rbx and the opaque arg in rbp (both are callee-saved, so
 * ContextSwitch's pop sequence leaves them in those registers). We move
 * arg into rdi (SysV first argument) and call entry. If entry ever
 * returns, we tail into SchedExitC so the task is cleanly marked Dead
 * rather than faulting on whatever sits above its stack.
 * ------------------------------------------------------------------------- */
.align 16
.global SchedTaskTrampoline
.type SchedTaskTrampoline, @function
SchedTaskTrampoline:
    /* Reached via `ret` from ContextSwitch (the stack primer planted
     * this address as the return target). `ret` is an indirect branch
     * from IBT's perspective: without an endbr here, the first
     * scheduler switch INTO a fresh task would raise #CP instead of
     * running the trampoline. */
    endbr64
    /* The first time we run a fresh task we arrive here via ret from
     * ContextSwitch, not via iretq — so RFLAGS.IF is whatever the prior
     * caller had. Typical path: Schedule() was invoked from the timer
     * IRQ dispatcher with IF=0. Unmask so the new task can be preempted
     * normally. On the "task previously switched out and back in" path
     * iretq restores the saved RFLAGS, so this sti is only actually
     * meaningful on the first-run-ever path. */
    sti
    mov     rdi, rbp
    call    rbx
    call    SchedExitC
    /* SchedExitC is [[noreturn]]; belt-and-braces if that's ever broken. */
    cli
    hlt
.size SchedTaskTrampoline, . - SchedTaskTrampoline


/* NX stack — silence lld's PT_GNU_STACK warning. */
.section .note.GNU-stack, "", @progbits
