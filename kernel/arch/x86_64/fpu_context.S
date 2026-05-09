/*
 * DuetOS — FPU / SSE / AVX context save and restore.
 *
 * Three primitives, all of which take a 64-byte aligned save area as
 * their first argument:
 *
 *   void FpuSaveXState   (void* save_area, u64 xfeature_mask);
 *   void FpuRestoreXState(const void* save_area, u64 xfeature_mask);
 *   void FpuInitState    (void* save_area);
 *
 * The mask argument selects which state components XSAVE / XRSTOR
 * touch. Pass 0 to fall back to the legacy FXSAVE / FXRSTOR pair (the
 * implementation branches on the mask being non-zero). The kernel
 * picks the mask once at boot from CPUID(0Dh,0):EAX&XCR0 and passes
 * the same value here on every save and matching restore.
 *
 * Why .S rather than inline asm:
 *
 *   - xsave64 / xrstor64 read EDX:EAX as a 64-bit feature mask. A
 *     C++ wrapper can express that with the right "a"/"d" inputs but
 *     loses the FXSAVE fallback under a single call — keeping both
 *     in one routine pins which instruction the kernel issued.
 *   - The save area MUST be 16-byte aligned (XSAVE in XSAVE-legacy
 *     mode requires 16; AVX components want 64). C-side alignment
 *     has to flow through the calling site; here we just trust the
 *     caller's pointer.
 *
 * Calling convention: SysV AMD64.
 *   rdi = save_area (16-byte aligned, 64 preferred)
 *   rsi = xfeature_mask  (FpuSaveXState / FpuRestoreXState only)
 *
 * Clobbers: rax, rdx (xsave/xrstor read EDX:EAX). All other GPRs
 * preserved per ABI.
 *
 * Does NOT touch interrupts. Caller (Schedule()) is already inside
 * a g_sched_lock-held section with IRQs disabled.
 */

.intel_syntax noprefix

.section .text

/* ------------------------------------------------------------------------- */
.align 16
.global FpuSaveXState
.type FpuSaveXState, @function
FpuSaveXState:
    endbr64
    /* If xfeature_mask == 0, fall back to FXSAVE — the CPU may not
     * advertise XSAVE at all, or this kernel was built without
     * relying on it. fxsave64 saves x87 + SSE state into the same
     * 512-byte FXSAVE area XSAVE-legacy uses; the layout is
     * compatible. */
    test    rsi, rsi
    jz      .Lfxsave

    /* xsave64 [save_area] using EDX:EAX as the feature mask. */
    mov     rax, rsi
    mov     rdx, rsi
    shr     rdx, 32
    xsave64 [rdi]
    ret

.Lfxsave:
    fxsave64 [rdi]
    ret
.size FpuSaveXState, . - FpuSaveXState


/* ------------------------------------------------------------------------- */
.align 16
.global FpuRestoreXState
.type FpuRestoreXState, @function
FpuRestoreXState:
    endbr64
    test    rsi, rsi
    jz      .Lfxrstor

    mov     rax, rsi
    mov     rdx, rsi
    shr     rdx, 32
    xrstor64 [rdi]
    ret

.Lfxrstor:
    fxrstor64 [rdi]
    ret
.size FpuRestoreXState, . - FpuRestoreXState


/* -------------------------------------------------------------------------
 * FpuInitState — produce a freshly-initialised XSAVE area.
 *
 * fninit puts the x87 stack into the architectural reset state. We
 * then write an MXCSR of 0x1F80 (all SSE exceptions masked, default
 * rounding) and zero the XSAVE header (the 64 bytes immediately
 * after the 512-byte legacy region) so XRSTOR sees XSTATE_BV = 0
 * and XCOMP_BV = 0 — meaning "everything is in the init state".
 *
 * The 512-byte FXSAVE area itself is intentionally NOT zeroed: an
 * xrstor with XSTATE_BV bit clear ignores its content and uses the
 * architectural init values regardless. We only touch the bytes
 * that XRSTOR actually reads (the header) plus the MXCSR slot
 * (offset 0x18) for completeness — debuggers tend to read it even
 * though XRSTOR ignores it when the SSE bit is clear.
 * ------------------------------------------------------------------------- */
.align 16
.global FpuInitState
.type FpuInitState, @function
FpuInitState:
    endbr64
    /* fninit writes the FPU control / status / tag registers and
     * does NOT raise exceptions if the FPU is in an exception-
     * pending state — fclex would. Init does both clear + reset. */
    fninit

    /* Default MXCSR. Bits 7..12 = exception masks (all set =
     * masked). The reserved-bit mask 0xFFFF ensures we don't
     * accidentally set an MBZ field if the field is later
     * extended. */
    mov     dword ptr [rdi + 0x18], 0x1F80

    /* Zero the 64-byte XSAVE header at offset 0x200. */
    xor     eax, eax
    mov     qword ptr [rdi + 0x200], rax
    mov     qword ptr [rdi + 0x208], rax
    mov     qword ptr [rdi + 0x210], rax
    mov     qword ptr [rdi + 0x218], rax
    mov     qword ptr [rdi + 0x220], rax
    mov     qword ptr [rdi + 0x228], rax
    mov     qword ptr [rdi + 0x230], rax
    mov     qword ptr [rdi + 0x238], rax
    ret
.size FpuInitState, . - FpuInitState


/* NX stack — silence lld's PT_GNU_STACK warning. */
.section .note.GNU-stack, "", @progbits
