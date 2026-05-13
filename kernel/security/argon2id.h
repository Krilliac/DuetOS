#pragma once

#include "util/types.h"

/*
 * DuetOS — Argon2id (RFC 9106), variable-length output.
 *
 * Memory-hard, time-cost-tunable password hash. Used by the
 * persistence layer to derive the KEK that wraps the on-disk
 * accounts / roles tables, and by `password_hash.cpp` as the v2
 * default password-hash algorithm.
 *
 * The implementation follows RFC 9106 (Argon2 v1.3) directly, with
 * the Argon2id mode (the first half of pass 0 is data-independent
 * Argon2i, every later block is data-dependent Argon2d). Built on
 * top of `security/blake2b.{h,cpp}` — no other crypto primitive is
 * referenced.
 *
 * Memory layout
 * -------------
 * Argon2id allocates `memory_kib` KiB up front. We obtain it from
 * the kernel heap (`mm::KMalloc`) on entry and free it on exit.
 * Production target (per wiki/security/Persistence.md) is 64 MiB;
 * v0 emulator profile is 16 KiB (cheap enough that the boot KAT
 * stays under a second). The kheap is currently sized at 2 MiB
 * (mm/kheap.h::kKernelHeapBytes), so callers MUST keep
 * `memory_kib` * 1024 strictly below the kheap budget — the v0
 * Argon2id call is the heaviest allocator in the kernel.
 *
 * The function is pure (no globals, no I/O, no syscalls beyond
 * KMalloc / KFree). Safe to call from any task context. NOT safe
 * from IRQ context (the heap allocator is not IRQ-safe).
 *
 * Test coverage
 * -------------
 * The boot self-test verifies against the RFC 9106 §5.3 Argon2id
 * test vector (p=4, t=3, m=32 KiB, tag=32 bytes). Any change to
 * the implementation that breaks the vector panics the boot.
 */

namespace duetos::security
{

constexpr u32 kArgon2idVersion = 0x13; // Argon2 v1.3
constexpr u32 kArgon2idTypeId = 2;     // 0=Argon2d, 1=Argon2i, 2=Argon2id
constexpr u32 kArgon2idBlockBytes = 1024;
constexpr u32 kArgon2idMaxTagBytes = 64;
constexpr u32 kArgon2idMinMemKib = 8; // RFC 9106 floor: 8p KiB; we pin p>=1 below

// Sensible upper bound for kernel-mode use. 1024 KiB == 1 MiB.
// Larger derivations need a bigger kheap (mm/kheap.h) or a direct
// frame-allocator path; both are slated future work. Today's 2 MiB
// kheap comfortably handles 1 MiB Argon2id allocations even with
// other kernel data structures live; bumping this caps blast radius
// on a wedged caller. Callers asking for more get a fail-closed
// `false` return from `Argon2idDerive`.
constexpr u32 kArgon2idMaxMemKib = 1024;

struct Argon2idParamsRuntime
{
    u32 memory_kib;  // total memory in KiB (multiple of 4*parallelism)
    u32 time_cost;   // number of passes (>= 1)
    u32 parallelism; // lanes (>= 1)
    u32 tag_len;     // output bytes [4, 64]
};

/// Derive `params.tag_len` bytes from (password, salt) under the
/// supplied Argon2id parameters. `out` must point to at least
/// `params.tag_len` bytes.
///
/// Returns false on parameter validation failure (out-of-range
/// memory, zero lanes/passes/tag, salt too short, memory budget
/// exceeded). Returns false on KMalloc failure (heap exhausted —
/// the kernel log records the failure at WARN).
///
/// `secret` and `ad` are optional Argon2 inputs ("K" and "X" in the
/// RFC). Pass nullptr/0 for the common password-hashing case where
/// neither is in play. Persistence callers use neither today.
bool Argon2idDerive(const u8* password, u32 password_len, const u8* salt, u32 salt_len, const u8* secret,
                    u32 secret_len, const u8* ad, u32 ad_len, const Argon2idParamsRuntime& params, u8* out);

/// RFC 9106 §5.3 KAT — derives the official Argon2id test vector
/// and panics on mismatch. Also exercises the variable-length-hash
/// (`H'`) path with `tag_len > 64` indirectly. Called from the boot
/// self-test list in `kernel/core/main.cpp`.
void Argon2idSelfTest();

} // namespace duetos::security
