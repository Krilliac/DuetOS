#pragma once

#include "types.h"

/*
 * CustomOS — kernel entropy source, v0.
 *
 * Three-stage entropy pool:
 *
 *   1. Hardware RDSEED  (if CpuFeatRdseed) — NIST-grade TRNG. Slow
 *      (100s of cycles per call, can fail on busy cores). Used for
 *      high-stakes consumers: KASLR, stack canaries, per-process
 *      ASLR.
 *
 *   2. Hardware RDRAND  (if CpuFeatRdrand) — NIST DRBG reseeded
 *      from RDSEED inside the CPU. Faster, always succeeds. Used
 *      as the workhorse for bulk fills.
 *
 *   3. Splitmix64(TSC)  — pure software fallback. Seeded from a
 *      mix of RDTSC + HPET counter + boot uptime at init time.
 *      Used on CPUs without RDRAND (ancient boxes, QEMU TCG
 *      without -cpu host). NOT cryptographic; flagged as such.
 *
 * Init logs the tier actually in use so a reader of the boot log
 * can tell at a glance whether ASLR/canaries have hardware
 * backing.
 *
 * Context: kernel.
 */

namespace customos::core
{

enum class EntropyTier : u8
{
    Splitmix = 0, // software fallback only
    Rdrand,       // CPU DRBG available
    Rdseed,       // CPU TRNG available (strictly stronger than Rdrand)
};

/// Seed the pool from TSC + HPET + uptime, probe RDRAND/RDSEED,
/// log the chosen tier. Safe single-init.
void RandomInit();

/// The tier the pool is currently operating at. Callers that
/// require hardware backing (kcrypto, key derivation) check this
/// before proceeding.
EntropyTier RandomCurrentTier();

/// Fill `buf` with `len` random bytes. Always succeeds — falls back
/// to splitmix on RDRAND/RDSEED retry-exhaustion.
void RandomFillBytes(void* buf, u64 len);

/// 64 bits of randomness.
u64 RandomU64();

/// Diagnostics counters. Visible via the `rand` shell command with
/// its `-s` flag (once landed).
struct RandomStats
{
    u64 rdseed_calls;
    u64 rdseed_successes;
    u64 rdrand_calls;
    u64 rdrand_successes;
    u64 splitmix_calls;
    u64 bytes_produced;
};
RandomStats RandomStatsRead();

/// Boot-time self-test: produces 64 bytes, asserts the buffer
/// isn't all-zeros / all-0xFF / trivially monotonic. Logs result.
void RandomSelfTest();

} // namespace customos::core
