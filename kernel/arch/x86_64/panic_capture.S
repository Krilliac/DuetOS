/*
 * kernel/arch/x86_64/panic_capture.S
 *
 * Naked shims for core::Panic / core::PanicWithValue / core::
 * PanicInProgressMark callers. Each shim captures the FULL
 * register state at the call site (before any C++ prologue
 * mutates anything) into the per-CPU PanicFrame from
 * panic_capture.h, then tail-calls the real C++ body.
 *
 * Convention (SysV x86_64):
 *   - Caller of Panic(subsystem, message) passed rdi=subsystem,
 *     rsi=message. We capture rdi/rsi as-is — they're the args,
 *     not pre-call state, but they're still the only register
 *     values the shim sees on entry. The OTHER 14 GPRs hold
 *     whatever the caller had right before the call, which is
 *     exactly what we want for the crash dump.
 *   - Return address ([rsp+0] at entry, before our subq) is
 *     the RIP that should follow the call — i.e. the caller's
 *     "next instruction" if it had returned. We capture it
 *     into rip_caller.
 *   - We MUST NOT push/pop anything before the captures — that
 *     would mutate rsp visibly. We capture rsp+8 as the
 *     caller's RSP (skipping the return address).
 *
 * Field offsets MUST match the PanicFrame struct in
 * panic_capture.h. If you reorder one, reorder the other and
 * audit. Layout pinned for inspection via gdb / objdump.
 */

    .text
    .extern duetos_arch_PanicFrameStorage_unused  /* keep linker honest */
    .extern PanicFrameRaw                         /* see below */

/* The .S file references the storage by absolute symbol via the
 * C++ wrapper helper, NOT via a direct C++ name (those get
 * mangled). panic_capture.cpp emits a C-linkage alias
 * `panic_frame_raw` pointing at the same bytes. We do that
 * indirection in a single TU so this .S file doesn't need to
 * know about C++ name mangling. */

/* Offsets into PanicFrame (must match panic_capture.h). */
    .set PF_rax,         0
    .set PF_rbx,         8
    .set PF_rcx,        16
    .set PF_rdx,        24
    .set PF_rsi,        32
    .set PF_rdi,        40
    .set PF_rbp,        48
    .set PF_rsp,        56
    .set PF_r8,         64
    .set PF_r9,         72
    .set PF_r10,        80
    .set PF_r11,        88
    .set PF_r12,        96
    .set PF_r13,       104
    .set PF_r14,       112
    .set PF_r15,       120
    .set PF_rip,       128
    .set PF_rflags,    136
    .set PF_cr0,       144
    .set PF_cr2,       152
    .set PF_cr3,       160
    .set PF_cr4,       168
    .set PF_valid,     176

/* CAPTURE_GPRS_INTO(target_symbol)
 *
 * Writes all 16 GPRs + caller RSP + return RIP + RFLAGS + CR0/2/3/4
 * + the valid sentinel into the bytes at `target_symbol`. Touches
 * %rax (used as the destination base) — preserves the caller's
 * %rax by storing it FIRST, before %rax gets re-loaded with the
 * frame address.
 *
 * Stomps RFLAGS via pushfq/popq; we capture RFLAGS first so this
 * doesn't matter. */
.macro CAPTURE_GPRS_INTO target
    /* Save the caller's %rax into a scratch slot in memory
     * (the rax field of the frame). We can do this without
     * touching %rax by going via [rip + target] + immediate
     * displacement. */
    movq    %rax, \target+PF_rax(%rip)
    /* %rax is now free. Load the frame base. (Even though we
     * stored via [rip + target] above, we still want %rax to
     * point at the frame for the rest of the macro — it
     * compiles to shorter encodings than 16 separate
     * rip-relative stores.) */
    leaq    \target(%rip), %rax
    movq    %rbx,   PF_rbx(%rax)
    movq    %rcx,   PF_rcx(%rax)
    movq    %rdx,   PF_rdx(%rax)
    movq    %rsi,   PF_rsi(%rax)
    movq    %rdi,   PF_rdi(%rax)
    movq    %rbp,   PF_rbp(%rax)
    /* Caller's RSP = current RSP + 8 (skip the return address
     * we pushed by being called). */
    movq    %rsp, %rbx                  /* clobber rbx — already saved */
    addq    $8, %rbx
    movq    %rbx,   PF_rsp(%rax)
    movq    %r8,    PF_r8(%rax)
    movq    %r9,    PF_r9(%rax)
    movq    %r10,   PF_r10(%rax)
    movq    %r11,   PF_r11(%rax)
    movq    %r12,   PF_r12(%rax)
    movq    %r13,   PF_r13(%rax)
    movq    %r14,   PF_r14(%rax)
    movq    %r15,   PF_r15(%rax)
    /* Caller's return RIP is at [rsp] (since we haven't pushed
     * anything). */
    movq    (%rsp), %rbx                /* rbx scratch — already saved */
    movq    %rbx,   PF_rip(%rax)
    /* RFLAGS via pushfq. pushfq decrements rsp by 8 — we restore
     * rsp via add below; this perturbs the saved RSP we captured
     * already, which is fine (the captured value was a copy). */
    pushfq
    popq    %rbx
    movq    %rbx,   PF_rflags(%rax)
    /* Control registers. CR2 is the PF fault address (valid for
     * #PF only, but harmless to capture). */
    movq    %cr0,   %rbx
    movq    %rbx,   PF_cr0(%rax)
    movq    %cr2,   %rbx
    movq    %rbx,   PF_cr2(%rax)
    movq    %cr3,   %rbx
    movq    %rbx,   PF_cr3(%rax)
    movq    %cr4,   %rbx
    movq    %rbx,   PF_cr4(%rax)
    /* Mark frame valid (>0). */
    movq    $1,     PF_valid(%rax)
    /* Restore the caller-visible %rax + %rbx by re-loading from
     * what we just stored. %rax goes last so the macro ends with
     * the original %rax value in the register. */
    movq    PF_rbx(%rax), %rbx
    movq    PF_rax(%rax), %rax
.endm

/* -------------------------------------------------------------------------
 * duetos_arch_PanicCaptureShim — entry the C++ Panic body
 * tail-calls right after deciding to halt. Captures state into
 * the global panic_frame storage and returns to the caller.
 *
 * Called from C++ as:
 *   extern "C" void duetos_arch_PanicCaptureShim();
 *
 * Idempotent (a recursive panic overwrites with the same
 * call-site state). Does not alter caller-visible registers.
 * ------------------------------------------------------------------------- */
    .globl  duetos_arch_PanicCaptureShim
    .type   duetos_arch_PanicCaptureShim, @function
duetos_arch_PanicCaptureShim:
    CAPTURE_GPRS_INTO panic_frame_raw
    retq
    .size   duetos_arch_PanicCaptureShim, . - duetos_arch_PanicCaptureShim
