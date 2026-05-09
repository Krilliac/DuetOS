#pragma once

#include "util/types.h"

/*
 * DuetOS — Win32 x64 SEH primitives.
 *
 * The two routines below are the foundation the SEH unwinder is
 * built on: capture the running CPU state into a Microsoft `CONTEXT`
 * struct, and restore execution from such a struct. Both follow the
 * Microsoft x64 ABI (first arg in RCX, NOT the SysV RDI), so they
 * are declared with `__attribute__((ms_abi))`.
 *
 * The full SEH dispatcher (RtlVirtualUnwind / RtlUnwindEx /
 * RtlLookupFunctionEntry, plus the kernel-side fault → user dispatch
 * path that builds the EXCEPTION_RECORD and jumps to ntdll's
 * KiUserExceptionDispatcher) is out of scope for this slice. These
 * primitives are what those higher layers will call.
 *
 * Context: kernel code that touches Win32 user state, or ntdll code
 * built with ms_abi calling convention.
 */

namespace duetos::win32
{

/// Microsoft `CONTEXT` (x64) — the subset the unwinder reads. Real
/// Win32 has more fields (debug regs, vector regs); we lay out the
/// struct at full size so the asm offsets in seh_unwind.S match
/// what binaries built against `<windows.h>` would observe. The
/// struct is 1232 bytes (0x4D0), aligned to 16.
struct alignas(16) Context
{
    u64 P[6]; ///< P1Home..P6Home
    u32 ContextFlags;
    u32 MxCsr;
    u16 SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
    u32 EFlags;
    u64 Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    u64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    u64 R8, R9, R10, R11, R12, R13, R14, R15;
    u64 Rip;
    u8 FltSave[512]; ///< XMM_SAVE_AREA32 (FXSAVE-shape)
    u8 VectorRegisters[26 * 16];
    u64 VectorControl;
    u64 DebugControl;
    u64 LastBranchToRip, LastBranchFromRip;
    u64 LastExceptionToRip, LastExceptionFromRip;
};

static_assert(sizeof(Context) == 0x4D0, "CONTEXT size must match Microsoft x64 layout");

} // namespace duetos::win32

extern "C"
{

    /// Capture caller's CPU state into `ctx`. Implemented in
    /// seh_unwind.S. The asm uses MS-ABI (first arg in RCX), but the
    /// declaration is plain extern "C" — it's the caller's
    /// responsibility to issue the call with MS-ABI in scope (e.g.
    /// `__attribute__((ms_abi))` on the wrapping function). User-mode
    /// ntdll runs MS-ABI by default; kernel callers should wrap.
    void RtlCaptureContext(duetos::win32::Context* ctx);

    /// Restore CPU state from `ctx` and resume at `ctx->Rip`. Does not
    /// return. `rec` is reserved for the unwinder; this primitive
    /// ignores it.
    [[noreturn]] void RtlRestoreContext(duetos::win32::Context* ctx, void* rec);

} // extern "C"
