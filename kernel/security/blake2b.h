#pragma once

#include "util/types.h"

/*
 * DuetOS — Blake2b (RFC 7693), variable-length output.
 *
 * Used by Argon2id (kernel/security/argon2id.{h,cpp}). Standalone
 * because the underlying primitive is small enough to be useful
 * elsewhere (future MAC paths, content-addressed storage, etc.).
 *
 * v0 supports unkeyed hashing only — no key, no salt, no
 * personalisation parameter (Argon2id doesn't need them; new
 * callers can grow the API when they do).
 *
 * Output length: 1..64 bytes. Argon2id calls with 64 (for H_0) and
 * with smaller sizes for the variable-length H' construction.
 *
 * Context: kernel. Computation is pure — no allocations, no I/O,
 * no scheduler interaction. Safe to call from any task context;
 * NOT safe in IRQ context (the state buffer is ~256 bytes — too
 * big for an IRQ-stack frame).
 */

namespace duetos::security
{

constexpr u32 kBlake2bMaxOutBytes = 64;
constexpr u32 kBlake2bBlockBytes = 128;

struct Blake2bState
{
    u64 h[8]; // chaining state
    u64 t[2]; // counter (low, high)
    u8 buf[kBlake2bBlockBytes];
    u32 buflen; // unprocessed bytes in buf
    u32 outlen; // requested digest size
};

/// Initialise for unkeyed hashing producing `out_bytes` output.
/// `out_bytes` must be in [1, 64].
void Blake2bInit(Blake2bState& s, u32 out_bytes);

/// Absorb `n` bytes from `in`.
void Blake2bUpdate(Blake2bState& s, const u8* in, u32 n);

/// Finalise — writes `s.outlen` bytes to `out`. The state is
/// left in an unspecified state after this; do not Update further.
void Blake2bFinal(Blake2bState& s, u8* out);

/// One-shot convenience.
void Blake2bHash(const u8* in, u32 in_len, u8* out, u32 out_bytes);

/// Boot self-test — verifies against the RFC 7693 test vector for
/// the empty message at output size 64 and against the string
/// "abc" at output size 64. Panics on regression.
void Blake2bSelfTest();

} // namespace duetos::security
