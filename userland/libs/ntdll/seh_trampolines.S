/*
 * userland/libs/ntdll/seh_trampolines.S
 *
 * SEH register-state trampolines exported by ntdll.dll. All three
 * routines operate on the Microsoft x64 CONTEXT record (the
 * Windows 64-bit equivalent of POSIX ucontext_t); offsets follow
 * the canonical layout shipped in winnt.h. They were previously
 * `__attribute__((naked)) __declspec(dllexport)` C entries with
 * the bodies as `__asm__ volatile` string blobs in
 * ntdll_seh.c / ntdll_dispatch.c — same fragility as the old
 * inline __chkstk before chkstk.S landed.
 *
 *   - RtlCaptureContext(rcx = CONTEXT*) — snapshot the caller's
 *     register state into the record. Rip = our return address,
 *     Rsp = caller's RSP *after* this routine returns. Naked
 *     because any compiler-emitted prologue would perturb the
 *     captured state.
 *
 *   - RtlRestoreContext(rcx = CONTEXT*, rdx = EXCEPTION_RECORD*)
 *     — load every register from the record and resume at
 *     ctx->Rip. The exception record is unused at this layer
 *     (kept in the signature for ABI compatibility with the
 *     Microsoft prototype). Never returns to the caller.
 *
 *   - KiUserExceptionDispatcher() — entry point the kernel
 *     resumes a faulting thread on. rcx = EXCEPTION_RECORD,
 *     rdx = CONTEXT, rsp pre-aligned to ((rsp & 0xF) == 8) per
 *     the post-CALL ABI shape. Reserves the 32-byte MS x64
 *     shadow area + 8 bytes for 16-byte alignment, then tails
 *     into the C dispatcher core which never returns.
 *
 * CONTEXT field offsets (Windows x64, MS_AMD64_ABI):
 *
 *   0x030  ContextFlags         (DWORD)
 *   0x044  EFlags               (DWORD)
 *   0x078  Rax
 *   0x080  Rcx
 *   0x088  Rdx
 *   0x090  Rbx
 *   0x098  Rsp
 *   0x0A0  Rbp
 *   0x0A8  Rsi
 *   0x0B0  Rdi
 *   0x0B8  R8
 *   0x0C0  R9
 *   0x0C8  R10
 *   0x0D0  R11
 *   0x0D8  R12
 *   0x0E0  R13
 *   0x0E8  R14
 *   0x0F0  R15
 *   0x0F8  Rip
 *   0x100  Xmm save area (FXSAVE format, 512 bytes)
 *
 * If you touch these offsets, audit every offset constant below
 * AND the matching offsets in the .c callers
 * (ctx_rip/ctx_rsp/ctx_reg helpers in ntdll_dispatch.c).
 */

    .text

/* -------------------------------------------------------------------------
 * RtlCaptureContext — snapshot caller state into rcx = CONTEXT*.
 * Microsoft x64 ABI: rcx is the first integer arg. We save it
 * before doing anything else (the entry value is the record
 * pointer; we capture it into ctx->Rcx so the dump reflects the
 * caller's intent), then dump GPRs, derive caller-Rsp / caller-
 * Rip from the on-stack return address, then EFlags and the
 * ContextFlags marker.
 * ------------------------------------------------------------------------- */
    .globl  RtlCaptureContext
    .def    RtlCaptureContext; .scl 2; .type 32; .endef
RtlCaptureContext:
    movq    %rax, 0x78(%rcx)
    movq    %rdx, 0x88(%rcx)
    movq    %rbx, 0x90(%rcx)
    movq    %rbp, 0xA0(%rcx)
    movq    %rsi, 0xA8(%rcx)
    movq    %rdi, 0xB0(%rcx)
    movq    %r8,  0xB8(%rcx)
    movq    %r9,  0xC0(%rcx)
    movq    %r10, 0xC8(%rcx)
    movq    %r11, 0xD0(%rcx)
    movq    %r12, 0xD8(%rcx)
    movq    %r13, 0xE0(%rcx)
    movq    %r14, 0xE8(%rcx)
    movq    %r15, 0xF0(%rcx)
    movq    %rcx, 0x80(%rcx)            /* captured Rcx = the record ptr arg */
    leaq    8(%rsp), %rax
    movq    %rax, 0x98(%rcx)            /* Rsp the caller sees after we return */
    movq    (%rsp), %rax
    movq    %rax, 0xF8(%rcx)            /* Rip = our return address */
    pushfq
    popq    %rax
    movl    %eax, 0x44(%rcx)            /* EFlags */
    movl    $0x0010000F, 0x30(%rcx)     /* ContextFlags = INTEGER|CONTROL|SEGMENTS|DEBUG_REGS */
    movq    0x78(%rcx), %rax            /* restore rax so the caller sees its original value */
    retq

/* -------------------------------------------------------------------------
 * RtlRestoreContext — restore every register from rcx = CONTEXT*
 * and resume at ctx->Rip. rdx (EXCEPTION_RECORD*) is unused at
 * this layer. Never returns.
 *
 * Plan: load every callee/caller-saved GPR, build a synthetic
 * return frame at ctx->Rsp-8 holding ctx->Rip, switch RSP, then
 * `ret` falls through to ctx->Rip. We restore the XMM save area
 * first via fxrstor64 since fxrstor doesn't touch GPRs / RFLAGS.
 * ------------------------------------------------------------------------- */
    .globl  RtlRestoreContext
    .def    RtlRestoreContext; .scl 2; .type 32; .endef
RtlRestoreContext:
    fxrstor64 0x100(%rcx)
    movl    0x44(%rcx), %eax
    pushq   %rax
    popfq                               /* EFlags restored */
    movq    0x90(%rcx), %rbx
    movq    0xA0(%rcx), %rbp
    movq    0xA8(%rcx), %rsi
    movq    0xB0(%rcx), %rdi
    movq    0xD8(%rcx), %r12
    movq    0xE0(%rcx), %r13
    movq    0xE8(%rcx), %r14
    movq    0xF0(%rcx), %r15
    movq    0xB8(%rcx), %r8
    movq    0xC0(%rcx), %r9
    movq    0xC8(%rcx), %r10
    movq    0xD0(%rcx), %r11
    movq    0xF8(%rcx), %rax            /* rax = target Rip */
    movq    0x98(%rcx), %rdx            /* rdx = target Rsp */
    subq    $8, %rdx
    movq    %rax, (%rdx)                /* [target_rsp - 8] = target Rip (synthetic ret) */
    movq    %rdx, %rsp                  /* switch to target stack */
    movq    0x78(%rcx), %rax            /* now restore the volatile args from the record */
    movq    0x88(%rcx), %rdx
    movq    0x80(%rcx), %rcx
    retq                                /* ret pops our synthesised Rip — resumes there */

/* -------------------------------------------------------------------------
 * KiUserExceptionDispatcher — kernel-resume entry point for
 * faulting user threads. On entry:
 *
 *   rcx = EXCEPTION_RECORD*
 *   rdx = CONTEXT*
 *   rsp aligned to ((rsp & 0xF) == 8)  (post-CALL ABI shape — the
 *                                       kernel's iretq+synthetic-CALL
 *                                       setup matches what an ordinary
 *                                       `call` would leave on rsp)
 *
 * Reserve 0x20 bytes of MS x64 shadow space + 8 bytes for 16-byte
 * pre-call alignment, then tail into KiUserExceptionDispatcherImpl
 * (lives in ntdll_dispatch.c). The impl never returns; if it ever
 * does, ud2 makes the misbehaviour loud rather than wandering off.
 * ------------------------------------------------------------------------- */
    .globl  KiUserExceptionDispatcher
    .def    KiUserExceptionDispatcher; .scl 2; .type 32; .endef
KiUserExceptionDispatcher:
    subq    $0x28, %rsp                 /* 0x20 shadow + 8 → 16-align before call */
    call    KiUserExceptionDispatcherImpl
    ud2                                 /* unreachable; impl is noreturn */
