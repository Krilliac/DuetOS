/*
 * DuetOS — x64 SEH primitives.
 *
 *   void RtlCaptureContext(CONTEXT* ctx);
 *   __attribute__((noreturn)) void RtlRestoreContext(CONTEXT* ctx,
 *                                                   EXCEPTION_RECORD* rec);
 *
 * Both are part of the public ntdll surface and are the foundations
 * the SEH unwinder is built on. `RtlCaptureContext` snapshots all
 * volatile and non-volatile GPRs + the legacy FPU + XMM0..XMM15 +
 * RIP/RSP/EFLAGS into a Microsoft `CONTEXT` struct, leaving the
 * caller's view of the world frozen at the moment of the call.
 * `RtlRestoreContext` reverses the operation: it loads every
 * register out of `CONTEXT` and resumes execution at the captured
 * RIP. The two together let the unwinder simulate the C++
 * exception-throw / catch transition on the Microsoft x64 ABI.
 *
 * Why .S: a C function fundamentally CANNOT capture its own
 * caller's RSP / RIP / non-volatile GPRs without depending on
 * the compiler's frame layout. Even a `__builtin_unwind_init` does
 * not reach RIP. Hand-written assembly is the only correct way to
 * implement these.
 *
 * CONTEXT struct layout (Microsoft x64). Offsets in bytes from the
 * start of the struct:
 *
 *   0x000  P1Home..P6Home      (6 * 8 = 0x30 bytes of arg-passing slots)
 *   0x030  ContextFlags        (u32)
 *   0x034  MxCsr               (u32)
 *   0x038  SegCs..SegSs        (6 * u16 = 0x0C; pad to align)
 *   0x044  EFlags              (u32)
 *   0x048  Dr0..Dr7            (6 * u64 = 0x30) — actually Dr0..Dr3, Dr6, Dr7
 *   0x078  Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi  (8 * u64 = 0x40)
 *   0x0B8  R8..R15             (8 * u64 = 0x40)
 *   0x0F8  Rip                 (u64)
 *   0x100  FltSave             (XMM_SAVE_AREA32, 0x200 bytes)
 *   0x300  VectorRegister[26]  (M128A * 26 = 0x1A0)
 *   0x4A0  VectorControl       (u64)
 *   0x4A8  DebugControl..Last  (5 * u64 = 0x28)
 *   0x4D0  Total size 0x4D0
 *
 * We populate the GPRs + RIP + RSP + EFlags subset that the
 * unwinder actually needs. FltSave is filled with FXSAVE so XMM
 * non-volatiles (XMM6..XMM15) survive the round trip; vector regs
 * and debug regs are left zero.
 */

.intel_syntax noprefix

.set CTX_MXCSR,    0x034
.set CTX_EFLAGS,   0x044
.set CTX_RAX,      0x078
.set CTX_RCX,      0x080
.set CTX_RDX,      0x088
.set CTX_RBX,      0x090
.set CTX_RSP,      0x098
.set CTX_RBP,      0x0A0
.set CTX_RSI,      0x0A8
.set CTX_RDI,      0x0B0
.set CTX_R8,       0x0B8
.set CTX_R9,       0x0C0
.set CTX_R10,      0x0C8
.set CTX_R11,      0x0D0
.set CTX_R12,      0x0D8
.set CTX_R13,      0x0E0
.set CTX_R14,      0x0E8
.set CTX_R15,      0x0F0
.set CTX_RIP,      0x0F8
.set CTX_FLTSAVE,  0x100

.section .text

/* -------------------------------------------------------------------------
 * RtlCaptureContext(CONTEXT* ctx)
 *
 * Microsoft x64 ABI: first arg in RCX (NOT RDI). The kernel side
 * uses SysV (RDI) and ntdll uses MS (RCX); we declare this with
 * `__attribute__((ms_abi))` on the C side, so the asm here pulls
 * the destination from RCX.
 *
 * Captured RSP is the value the caller had — i.e. the value AFTER
 * the call instruction's `push rip`. We undo that by reading RSP
 * and adding 8.
 *
 * Captured RIP is the return address sitting at [rsp+0]: the
 * instruction the caller will resume on after RtlCaptureContext
 * returns.
 * ------------------------------------------------------------------------- */
.align 16
.global RtlCaptureContext
.type RtlCaptureContext, @function
RtlCaptureContext:
    endbr64
    /* Volatile GPRs first — caller might still be using them, so
     * we record exactly what they hold at this instant. */
    mov     [rcx + CTX_RAX], rax
    mov     [rcx + CTX_RDX], rdx
    mov     [rcx + CTX_R8],  r8
    mov     [rcx + CTX_R9],  r9
    mov     [rcx + CTX_R10], r10
    mov     [rcx + CTX_R11], r11

    /* Non-volatile GPRs. The caller hasn't touched these since
     * its prologue, so they reflect the caller's state. */
    mov     [rcx + CTX_RBX], rbx
    mov     [rcx + CTX_RBP], rbp
    mov     [rcx + CTX_RSI], rsi
    mov     [rcx + CTX_RDI], rdi
    mov     [rcx + CTX_R12], r12
    mov     [rcx + CTX_R13], r13
    mov     [rcx + CTX_R14], r14
    mov     [rcx + CTX_R15], r15

    /* Capture RCX itself — the destination pointer doubles as the
     * value we hand back. The caller's RCX held this value before
     * calling. */
    mov     [rcx + CTX_RCX], rcx

    /* Caller's RSP = our RSP + 8 (one return address). */
    lea     rax, [rsp + 8]
    mov     [rcx + CTX_RSP], rax

    /* Return address from the call site. */
    mov     rax, [rsp]
    mov     [rcx + CTX_RIP], rax

    /* EFLAGS via pushfq -> pop. Reasonable approximation: the
     * compare/test result the caller saw immediately before the
     * call lives in EFLAGS at this moment. */
    pushfq
    pop     rax
    mov     [rcx + CTX_EFLAGS], eax

    /* MXCSR + XMM. fxsave64 writes a 512-byte XMM_SAVE_AREA32
     * starting at FltSave. Alignment: rcx may not be 16-aligned,
     * but the CONTEXT struct has the FltSave field 16-aligned by
     * its declaration. We trust the C++ caller to honour
     * __declspec(align(16)). */
    fxsave64 [rcx + CTX_FLTSAVE]
    ret
.size RtlCaptureContext, . - RtlCaptureContext


/* -------------------------------------------------------------------------
 * RtlRestoreContext(CONTEXT* ctx, EXCEPTION_RECORD* rec)
 *
 * Microsoft x64 ABI: rcx = ctx, rdx = rec. The exception record
 * argument is unused at this layer — higher-level callers may
 * inspect it before calling us.
 *
 * Implementation: load every saved register, then reconstruct an
 * iretq-style frame on the resumption stack and use a manual
 * `mov rsp ; jmp [resume_rip]` sequence. We can't iretq because
 * we may be running in user mode; iretq would fault.
 *
 * The resumption sequence:
 *   1. Load every non-volatile + volatile GPR EXCEPT rax / rcx /
 *      rsp from the CONTEXT.
 *   2. Switch to the captured RSP — but write the captured RIP
 *      to [new_rsp - 8] first, so a `jmp` after RSP reload acts
 *      like a `ret` to the captured RIP.
 *   3. Reload rax (target of the `jmp`-via-memory? we do an
 *      indirect via a register the caller doesn't observe), then
 *      `jmp` through it.
 *
 * Actual sequence below uses rax as the scratch, since rax is
 * volatile and the caller can't tell we trashed it (it's about
 * to be overwritten by `mov eax, [ctx+CTX_RAX]` anyway).
 * ------------------------------------------------------------------------- */
.align 16
.global RtlRestoreContext
.type RtlRestoreContext, @function
RtlRestoreContext:
    endbr64
    /* Restore XMM + MXCSR via fxrstor before we lose access to
     * rcx as the CONTEXT pointer. */
    fxrstor64 [rcx + CTX_FLTSAVE]

    /* Restore EFLAGS via push/popfq. Doing this early so the
     * volatile-GPR loads below don't have their own ALU side-
     * effects clobbered by a late popfq. */
    mov     eax, [rcx + CTX_EFLAGS]
    push    rax
    popfq

    /* Load non-volatiles. */
    mov     rbx, [rcx + CTX_RBX]
    mov     rbp, [rcx + CTX_RBP]
    mov     rsi, [rcx + CTX_RSI]
    mov     rdi, [rcx + CTX_RDI]
    mov     r12, [rcx + CTX_R12]
    mov     r13, [rcx + CTX_R13]
    mov     r14, [rcx + CTX_R14]
    mov     r15, [rcx + CTX_R15]

    /* Load volatiles. r10/r11 are restored before rax/rdx because
     * they double as MS-ABI scratch. */
    mov     r8,  [rcx + CTX_R8]
    mov     r9,  [rcx + CTX_R9]
    mov     r10, [rcx + CTX_R10]
    mov     r11, [rcx + CTX_R11]

    /* Build the "synthetic ret frame" on the captured RSP:
     *   [target_rsp - 8] = target_rip
     * Then we'll switch to (target_rsp - 8) and execute `ret`,
     * which pops target_rip into RIP exactly. */
    mov     rax, [rcx + CTX_RIP]
    mov     rdx, [rcx + CTX_RSP]
    sub     rdx, 8
    mov     [rdx], rax

    /* Now reload rax / rdx from the saved CONTEXT (their actual
     * values), and rcx last because we've been using it as the
     * struct pointer. The new RSP is in a callee-saved scratch
     * we haven't committed yet — store it in r11 temporarily,
     * since the popfq above already loaded the user-visible r11
     * value... wait, we loaded r11 above. Use rax as scratch:
     * we already have target_rsp-8 in rdx, target_rip on stack
     * at [rdx]. Sequence:
     *
     *   mov rsp, rdx       ; switch stacks (rsp now = target_rsp-8)
     *   mov rax, [rcx + RAX]
     *   mov rdx, [rcx + RDX]
     *   mov rcx, [rcx + RCX]
     *   ret                ; pops target_rip into RIP, rsp -> target_rsp
     *
     * After `ret`, RSP exactly matches the captured RSP and RIP
     * is the captured RIP, with every other register restored. */
    mov     rsp, rdx
    mov     rax, [rcx + CTX_RAX]
    mov     rdx, [rcx + CTX_RDX]
    mov     rcx, [rcx + CTX_RCX]
    ret
.size RtlRestoreContext, . - RtlRestoreContext


.section .note.GNU-stack, "", @progbits
