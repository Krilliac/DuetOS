/*
 * DuetOS — Intel CET probe, v0 (plan E1).
 *
 * Reads CPUID(7,0) for the SS / IBT support bits and stashes
 * them in a global. v0 ENABLE path is deliberately absent —
 * landing the probe first lets a future slice gate the
 * `IA32_S_CET` writes + shadow-stack allocations on a real
 * signal rather than a static config knob.
 */

#include "arch/x86_64/cet.h"

#include "arch/x86_64/serial.h"

namespace duetos::arch
{

namespace
{

CetStatus g_cet = {};
bool g_done = false;

struct Cpuid
{
    u32 eax, ebx, ecx, edx;
};

Cpuid DoCpuid(u32 leaf, u32 subleaf = 0)
{
    Cpuid r;
    asm volatile("cpuid" : "=a"(r.eax), "=b"(r.ebx), "=c"(r.ecx), "=d"(r.edx) : "a"(leaf), "c"(subleaf));
    return r;
}

} // namespace

void CetProbe()
{
    if (g_done)
    {
        return;
    }
    g_done = true;

    // Highest standard CPUID leaf must include 7 to read the
    // CET bits. Older silicon (~Skylake-X and below) doesn't
    // expose them at all; the probe leaves both `supported`
    // booleans false in that case.
    Cpuid r0 = DoCpuid(0);
    if (r0.eax < 7)
    {
        SerialWrite("[cpu] cet: no leaf 7; CET not detectable on this CPU\n");
        return;
    }

    // Leaf 7, sub-leaf 0:
    //   ECX[7]  = CET-SS
    //   EDX[20] = CET-IBT
    Cpuid r7 = DoCpuid(7, 0);
    g_cet.ss_supported = (r7.ecx & (1U << 7)) != 0;
    g_cet.ibt_supported = (r7.edx & (1U << 20)) != 0;
    // Enable bits stay false in v0 — the probe doesn't write
    // IA32_S_CET. A future E1-followup gates the writes on
    // ss_supported / ibt_supported.

    SerialWrite("[cpu] cet: ss=");
    SerialWrite(g_cet.ss_supported ? "supported" : "absent");
    SerialWrite(" ibt=");
    SerialWrite(g_cet.ibt_supported ? "supported" : "absent");
    SerialWrite(" (enable deferred to E1-followup)\n");
}

const CetStatus& CetGet()
{
    return g_cet;
}

} // namespace duetos::arch
