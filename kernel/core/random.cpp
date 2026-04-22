#include "random.h"

#include "../arch/x86_64/cpu_info.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/timer.h"
#include "klog.h"
#include "panic.h"

namespace customos::core
{

namespace
{

EntropyTier g_tier = EntropyTier::Splitmix;
u64 g_splitmix_state = 0;
RandomStats g_stats = {};

// Classic splitmix64. Cheap + decent distribution for a
// fallback PRNG — matches what Go, Java, and D use internally.
// NOT cryptographic.
u64 Splitmix64(u64& state)
{
    state += 0x9E3779B97F4A7C15ULL;
    u64 z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

u64 ReadTsc()
{
    u32 lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (u64(hi) << 32) | lo;
}

// RDRAND wrapper — retries up to 10x per the Intel recommendation.
// CF set on success. Returns true iff a valid 64-bit value was
// obtained.
bool TryRdrand(u64& out)
{
    ++g_stats.rdrand_calls;
    for (u32 i = 0; i < 10; ++i)
    {
        u64 val;
        u8 cf;
        asm volatile("rdrand %0; setc %1" : "=r"(val), "=r"(cf));
        if (cf)
        {
            out = val;
            ++g_stats.rdrand_successes;
            return true;
        }
    }
    return false;
}

// RDSEED wrapper — same shape, different MSR. RDSEED can fail more
// often under load; Intel recommends up to 100 retries for seed
// stretching. We compromise at 32 to bound latency.
bool TryRdseed(u64& out)
{
    ++g_stats.rdseed_calls;
    for (u32 i = 0; i < 32; ++i)
    {
        u64 val;
        u8 cf;
        asm volatile("rdseed %0; setc %1" : "=r"(val), "=r"(cf));
        if (cf)
        {
            out = val;
            ++g_stats.rdseed_successes;
            return true;
        }
    }
    return false;
}

// Pick the best source available. Updates stats. Falls back to
// splitmix on repeated hardware-source failure.
u64 GenU64()
{
    u64 v;
    if (g_tier == EntropyTier::Rdseed && TryRdseed(v))
        return v;
    if (g_tier >= EntropyTier::Rdrand && TryRdrand(v))
        return v;
    ++g_stats.splitmix_calls;
    return Splitmix64(g_splitmix_state);
}

} // namespace

void RandomInit()
{
    static constinit bool s_done = false;
    KASSERT(!s_done, "core/random", "RandomInit called twice");
    s_done = true;

    // Seed the software fallback from every clock we have access
    // to. XOR-mix rather than XXH / SipHash — the goal here is
    // "not the same boot-to-boot", not cryptographic strength
    // (which only comes from hardware anyway).
    g_splitmix_state = ReadTsc();
    g_splitmix_state ^= arch::HpetReadCounter();
    g_splitmix_state ^= u64(arch::TimerTicks()) << 32;
    if (g_splitmix_state == 0)
        g_splitmix_state = 0xCAFEBABE12345678ULL;

    // Pick the highest tier the CPU advertises, verified by one
    // successful read.
    if (arch::CpuHas(arch::kCpuFeatRdseed))
    {
        u64 probe;
        if (TryRdseed(probe))
        {
            g_tier = EntropyTier::Rdseed;
        }
    }
    if (g_tier < EntropyTier::Rdseed && arch::CpuHas(arch::kCpuFeatRdrand))
    {
        u64 probe;
        if (TryRdrand(probe))
        {
            g_tier = EntropyTier::Rdrand;
        }
    }

    arch::SerialWrite("[random] tier=");
    switch (g_tier)
    {
    case EntropyTier::Rdseed:
        arch::SerialWrite("RDSEED (NIST TRNG)");
        break;
    case EntropyTier::Rdrand:
        arch::SerialWrite("RDRAND (NIST DRBG — no RDSEED on this CPU)");
        break;
    default:
        arch::SerialWrite("splitmix64 (TSC-seeded — NOT cryptographic)");
        break;
    }
    arch::SerialWrite("\n");
}

EntropyTier RandomCurrentTier()
{
    return g_tier;
}

void RandomFillBytes(void* buf, u64 len)
{
    if (buf == nullptr || len == 0)
        return;
    auto* dst = static_cast<u8*>(buf);
    u64 i = 0;
    while (i + 8 <= len)
    {
        const u64 v = GenU64();
        for (u64 b = 0; b < 8; ++b)
            dst[i + b] = u8((v >> (b * 8)) & 0xFF);
        i += 8;
    }
    if (i < len)
    {
        const u64 v = GenU64();
        for (u64 b = 0; i < len; ++b, ++i)
            dst[i] = u8((v >> (b * 8)) & 0xFF);
    }
    g_stats.bytes_produced += len;
}

u64 RandomU64()
{
    const u64 v = GenU64();
    g_stats.bytes_produced += 8;
    return v;
}

RandomStats RandomStatsRead()
{
    return g_stats;
}

Uuid UuidV4()
{
    Uuid u;
    RandomFillBytes(u.bytes, 16);
    // Version 4 — high nibble of byte 6 = 0100.
    u.bytes[6] = u8((u.bytes[6] & 0x0F) | 0x40);
    // Variant 10 — high two bits of byte 8 = 10.
    u.bytes[8] = u8((u.bytes[8] & 0x3F) | 0x80);
    return u;
}

void UuidFormat(const Uuid& u, char* out)
{
    if (out == nullptr)
        return;
    static const char hex[] = "0123456789abcdef";
    // Dash positions in the canonical form:
    //   8-4-4-4-12 chars = dashes after bytes 3, 5, 7, 9 (1-based index).
    u64 pos = 0;
    for (u64 i = 0; i < 16; ++i)
    {
        out[pos++] = hex[(u.bytes[i] >> 4) & 0x0F];
        out[pos++] = hex[u.bytes[i] & 0x0F];
        if (i == 3 || i == 5 || i == 7 || i == 9)
            out[pos++] = '-';
    }
    out[pos] = '\0';
}

void RandomSelfTest()
{
    u8 buf[64];
    RandomFillBytes(buf, sizeof(buf));
    // Sanity asserts — none are cryptographic, just "did the
    // generator do something". A real RNG test (entropy estimate,
    // Dieharder, NIST STS) is user-space.
    bool all_zero = true;
    bool all_ff = true;
    bool monotonic = true;
    u8 prev = buf[0];
    for (u64 i = 0; i < sizeof(buf); ++i)
    {
        if (buf[i] != 0)
            all_zero = false;
        if (buf[i] != 0xFF)
            all_ff = false;
        if (i > 0 && buf[i] != u8(prev + 1))
            monotonic = false;
        prev = buf[i];
    }
    if (all_zero || all_ff || monotonic)
    {
        Log(LogLevel::Warn, "core/random", "self-test failed — all-zero / all-ff / monotonic");
        return;
    }
    arch::SerialWrite("[random] self-test OK — 64 bytes non-trivial (first 8 = ");
    for (u64 i = 0; i < 8; ++i)
    {
        if (i != 0)
            arch::SerialWrite(":");
        arch::SerialWriteHex(buf[i]);
    }
    arch::SerialWrite(")\n");

    // UUID self-test: generate one, format it, verify the
    // version + variant bits are set correctly per RFC 4122.
    const Uuid u = UuidV4();
    char uuid_str[37];
    UuidFormat(u, uuid_str);
    const u8 ver = (u.bytes[6] >> 4) & 0x0F;
    const u8 var = (u.bytes[8] >> 6) & 0x03;
    if (ver != 4 || var != 0b10)
    {
        Log(LogLevel::Warn, "core/random", "UUID self-test failed — version/variant bits wrong");
    }
    else
    {
        arch::SerialWrite("[uuid] v4 self-test OK — ");
        arch::SerialWrite(uuid_str);
        arch::SerialWrite(" (version=4 variant=10)\n");
    }
}

} // namespace customos::core
