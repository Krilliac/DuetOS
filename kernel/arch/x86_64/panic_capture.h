#pragma once

#include "util/types.h"

/*
 * kernel/arch/x86_64/panic_capture.h
 *
 * Frozen-state register snapshot taken at the FIRST instruction
 * of the panic entry path, before any C++ prologue mutates the
 * caller's registers. The C++ Panic() / PanicWithValue() entries
 * are wrappers around the naked .S shims defined in
 * panic_capture.S; the shims fill in a per-CPU PanicFrame, then
 * tail-call into the real C++ body, which now has access to the
 * caller's register state via PanicFrameLast().
 *
 * Without this, the crash-dump GPR table shows registers as they
 * stood AFTER the call's prologue — RAX often 0x1 (the boolean
 * return of the cmp that branched to Panic), RBP and RBX
 * already saved to the new frame, etc. Investigating from those
 * values is misleading. With this, the dump shows the caller's
 * state EXACTLY as it was at the instant the panic decision was
 * made.
 *
 * Cost: one cache-line write on every Panic, zero on the non-
 * panic path. The shim is only entered during a halt, so it's
 * far off the hot path.
 */

namespace duetos::arch
{

/// Snapshot of every interesting register at the moment the
/// panic shim was entered, before any C++ prologue ran. All
/// fields are zero-initialised at boot; the shim writes them
/// on every panic. Layout MUST match the .S shim's stores —
/// offsets are baked into the assembly.
struct PanicFrame
{
    u64 rax;
    u64 rbx;
    u64 rcx;
    u64 rdx;
    u64 rsi;
    u64 rdi;
    u64 rbp;
    u64 rsp; // caller's RSP, NOT the panic shim's
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
    u64 rip_caller; // return address into the caller of Panic
    u64 rflags;
    u64 cr0;
    u64 cr2;
    u64 cr3;
    u64 cr4;
    u64 valid; // 0 = not yet populated; 1 = populated this boot
};

/// Pointer to the per-CPU panic frame. On the first panic on
/// any CPU, populated by the .S shim; on subsequent panics,
/// overwritten. `valid` is 1 iff at least one panic has fired
/// since boot.
///
/// Today: returns a single global frame (one panic-at-a-time
/// is the design; PanicInProgress prevents concurrent panics).
/// SMP-per-CPU follow-up if cross-CPU panics ever become a
/// concern (they won't — Panic broadcasts an NMI that halts
/// peers).
const PanicFrame* PanicFrameLast();

/// Mutable pointer for the .S shim. Not part of the public
/// API — exposed so the shim can store via an absolute symbol
/// without needing a getter call. Layout-only consumers
/// (`PanicFrameLast()`) should prefer the const variant.
PanicFrame* PanicFrameStorage();

} // namespace duetos::arch
