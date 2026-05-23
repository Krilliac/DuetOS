/*
 * DuetOS — kernel thread context switch.
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
     *     quad of alignment padding above it.
     *
     * BUT only if the value at [rsp] is canonical kernel text. A 32-bit
     * truncation / partial scribble of that slot (sibling shape of
     * canary13's RA-slot bug + canary14's kstack-TLB-stale bug) would
     * make this `ret` silently dispatch to a low-canonical wild RIP —
     * the kernel jumps to a never-mapped user-half address and the
     * faulting CPU has no indirect-call site to attribute the trap to.
     *
     * The kernel already gates every OTHER kernel control transfer
     * through a target-range check:
     *   - indirect calls / jmps  -> __llvm_retpoline_r11 (range-check r11)
     *   - kernel-mode iretq      -> isr_common epilogue (range-check saved RIP)
     *   - trampoline `call rbx`  -> SchedTaskTrampolineValidateEntry
     *
     * The one un-gated path was THIS `ret`. Close it: bounds-check the
     * value at [rsp] against [_text_start, _text_end) before yielding
     * control. Catches a primed-slot truncation BEFORE RIP is set, with
     * a real banner naming the resuming task instead of a wild #PF whose
     * RIP is the truncated value.
     *
     * Observed once on `claude/assembly-files-review-ju0dI`: #PF at
     * instruction fetch of 0x00000000803b9ae3 (low-canonical mirror of
     * a high-half symbol) with CS=0x08 and no preceding gate banner.
     *
     * rax + rcx are SysV caller-saved — clobbering them across this
     * `ret` is invisible to the resumed code. Cost: 2 push, 2 movabs,
     * 2 cmp, 2 pop on every switch-in. Negligible vs the
     * ContextSwitch + TLB cost. */
    push    rax
    push    rcx
    movabs  rax, offset _text_start
    movabs  rcx, offset _text_end
    cmp     qword ptr [rsp + 16], rax  /* ret target at [rsp+16] after our 2 pushes */
    jb      .Lcs_wild_ret
    cmp     qword ptr [rsp + 16], rcx
    jae     .Lcs_wild_ret
    pop     rcx
    pop     rax
    ret

.Lcs_wild_ret:
    /* The about-to-be-popped return target is out of [_text_start,
     * _text_end). Hand the wild value to a C helper that emits a
     * real banner naming the resuming CPU + task and panics cleanly.
     * SchedContextSwitchWildRetCallback is [[noreturn]]; cli/hlt
     * below is belt-and-braces. */
    mov     rdi, qword ptr [rsp + 16]
    pop     rcx
    pop     rax
    call    SchedContextSwitchWildRetCallback
    cli
    hlt

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
    /* Reserve 16 bytes so RSP never sits at slot_top while IRQs are
     * enabled. After ContextSwitch's `ret` (which consumes the
     * planted &SchedTaskTrampoline at slot_top-8), RSP=slot_top. If
     * an IRQ fires while RSP=slot_top, hardware pushes a 40-byte
     * iretq frame whose top quad (SS) lands at slot_top-8 — the
     * planted RA slot — overwriting it with kKernelDataSelector
     * (= 0x10). The slot-validator in Schedule() then panics on the
     * task's next switch-in with `observed=0x10`. (~60% on SMP=8
     * release boots, traced 2026-05-22: every reproduction has
     * exactly observed=0x10, value of kKernelDataSelector.)
     *
     * `sub rsp, 16` keeps the planted RA slot below RSP for the
     * entire trampoline lifetime, so IRQ-frame SS pushes land at
     * slot_top-24 (= RSP-8 = (slot_top-16)-8) and the planted RA at
     * slot_top-8 is preserved. 16 (not 8) keeps RSP 16-aligned per
     * SysV — calls expect (RSP+8) mod 16 == 0 on entry. The
     * reserved 8 bytes between RSP and the planted RA are dead —
     * never read, never written by trampoline code. */
    sub     rsp, 16
    /* Drain this CPU's lock-pass slot. The Schedule() call that
     * switched INTO this fresh task left g_sched_lock held; we own
     * the release. SchedFinishTaskSwitch is callee-saved-clean
     * (extern "C", no args), so rbx (entry) and rbp (arg) survive
     * the call and the existing first-run primer wiring still
     * works. */
    call    SchedFinishTaskSwitch
    /* The first time we run a fresh task we arrive here via ret from
     * ContextSwitch, not via iretq — so RFLAGS.IF is whatever the prior
     * caller had. Typical path: Schedule() was invoked from the timer
     * IRQ dispatcher with IF=0. Unmask so the new task can be preempted
     * normally. On the "task previously switched out and back in" path
     * iretq restores the saved RFLAGS, so this sti is only actually
     * meaningful on the first-run-ever path. */
    sti
    /* Diagnostic: validate the planted entry function (rbx) is in
     * kernel .text range BEFORE we indirect-call it. The trampoline
     * is the ONLY indirect call to rbx on the fresh-task path, so a
     * corrupted plant lands here. The validator (extern "C", no
     * return value, first arg in rdi) panics with a real banner if
     * rbx fell out of [_text_start, _text_end). rbx is callee-saved
     * by SysV ABI and the validator is `extern "C"`, so rbx survives
     * the call and `call rbx` below still dispatches the same value
     * the validator just inspected. rdi gets clobbered (caller-saved)
     * — re-set from rbp on the next instruction. Observed
     * 2026-05-22: ~1/10 SMP=8 boots faulted at a wild rip
     * (0x101e / 0xffffffff8132axxx) inside this trampoline path
     * before this gate was added. */
    mov     rdi, rbx
    call    SchedTaskTrampolineValidateEntry
    mov     rdi, rbp
    call    rbx
    call    SchedExitC
    /* SchedExitC is [[noreturn]]; belt-and-braces if that's ever broken. */
    cli
    hlt
.size SchedTaskTrampoline, . - SchedTaskTrampoline


/* NX stack — silence lld's PT_GNU_STACK warning. */
.section .note.GNU-stack, "", @progbits
