/*
 * DuetOS — saturating arithmetic implementation.
 *
 * Owns the klog-emit path for clamp events + the boot self-test.
 * The arithmetic templates live entirely in `saturating.h`; this
 * TU exists for the symbol-resolving diagnostic and the self-test
 * harness (both heavy enough to not inline into every header).
 */

#include "util/saturating.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "util/symbols.h"

namespace duetos::util
{

namespace
{

// Bumped on every clamp event. Read by the shell `inspect sat`
// (future) and the boot self-test, which asserts a clean delta.
constinit u64 g_clamp_events = 0;

// Suppress floods. A single buggy call site can emit thousands of
// clamp events per second; one log line per cluster + the running
// counter is enough to triage from the boot log, and the kernel
// keeps making forward progress.
constexpr u64 kClampLogRateLimit = 32;

// Print " caller=[name+0xOFF (file:line)]" or " caller=<addr>".
void EmitCaller(u64 caller_rip)
{
    arch::SerialWrite(" caller=");
    core::SymbolResolution res;
    if (core::ResolveAddress(caller_rip, &res))
    {
        core::WriteAddressWithSymbol(caller_rip);
    }
    else
    {
        arch::SerialWriteHex(caller_rip);
    }
}

} // namespace

void SatLogClamp(const char* tag, u64 attempted, u64 clamped, void* caller_rip)
{
    ++g_clamp_events;
    if (g_clamp_events > kClampLogRateLimit)
    {
        return; // throttled; reading g_clamp_events still reflects the truth
    }
    arch::SerialWrite("\n[t~?] [W] util/saturating : clamp ");
    arch::SerialWrite(tag);
    arch::SerialWrite("   attempted=");
    arch::SerialWriteHex(attempted);
    arch::SerialWrite(" clamped_to=");
    arch::SerialWriteHex(clamped);
    EmitCaller(reinterpret_cast<u64>(caller_rip));
    arch::SerialWrite("\n");
}

void SaturatingSelfTest()
{
    arch::SerialWrite("[util/saturating] self-test\n");

    // Add: 0xFFFFFFFF + 1 (u32) must clamp to 0xFFFFFFFF.
    {
        const u32 a = 0xFFFFFFFFu;
        const u32 b = 1u;
        const u32 r = SatAdd<u32>(a, b);
        KASSERT(r == 0xFFFFFFFFu, "util/saturating",
                "self-test: SatAdd u32 max+1 should clamp to max");
    }
    // Add: 5 + 7 (u32) must be 12, no clamp.
    {
        const u32 r = SatAdd<u32>(5u, 7u);
        KASSERT(r == 12u, "util/saturating",
                "self-test: SatAdd 5+7 should be 12");
    }
    // Sub: 0 - 1 (u32) must clamp to 0.
    {
        const u32 r = SatSub<u32>(0u, 1u);
        KASSERT(r == 0u, "util/saturating",
                "self-test: SatSub u32 0-1 should clamp to 0");
    }
    // Sub: 10 - 3 (u32) must be 7, no clamp.
    {
        const u32 r = SatSub<u32>(10u, 3u);
        KASSERT(r == 7u, "util/saturating",
                "self-test: SatSub 10-3 should be 7");
    }
    // Mul: 0x10000 * 0x10000 (u32) must clamp to 0xFFFFFFFF.
    {
        const u32 r = SatMul<u32>(0x10000u, 0x10000u);
        KASSERT(r == 0xFFFFFFFFu, "util/saturating",
                "self-test: SatMul u32 0x10000*0x10000 should clamp to max");
    }
    // Mul: 100 * 200 (u32) must be 20000, no clamp.
    {
        const u32 r = SatMul<u32>(100u, 200u);
        KASSERT(r == 20000u, "util/saturating",
                "self-test: SatMul 100*200 should be 20000");
    }
    // u64 add edge.
    {
        const u64 r = SatAdd<u64>(0xFFFFFFFFFFFFFFFFull, 1ull);
        KASSERT(r == 0xFFFFFFFFFFFFFFFFull, "util/saturating",
                "self-test: SatAdd u64 max+1 should clamp to max");
    }
    // Wrapper type ++ saturates at max.
    {
        SatU8 c{255};
        ++c;
        KASSERT(static_cast<u8>(c) == 255, "util/saturating",
                "self-test: SatU8 ++ at max should saturate");
    }
    // Wrapper type -- saturates at 0.
    {
        SatU16 c{0};
        --c;
        KASSERT(static_cast<u16>(c) == 0, "util/saturating",
                "self-test: SatU16 -- at 0 should saturate");
    }
    // Wrapper type += normal path.
    {
        SatU32 c{100u};
        c += 50u;
        KASSERT(static_cast<u32>(c) == 150u, "util/saturating",
                "self-test: SatU32 += in-range should add normally");
    }

    arch::SerialWrite("[util/saturating] self-test OK\n");
}

} // namespace duetos::util
