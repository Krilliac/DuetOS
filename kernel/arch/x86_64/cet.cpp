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

#include "arch/x86_64/cpu.h"
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

    // CR4.CET live state (bit 23). Firmware / hypervisor MAY
    // enable CR4.CET before the kernel starts; we surface that
    // here so the boot log reflects the actual hardware
    // posture instead of "false in v0" lies.
    constexpr u64 kCr4CetBit = 1ull << 23;
    g_cet.cr4_cet_set = (ReadCr4() & kCr4CetBit) != 0;

    // IA32_S_CET MSR value. Only readable when CR4.CET is set;
    // otherwise the MSR read can #GP on some implementations.
    // Read only when we know it's safe (either ss or ibt is in
    // silicon AND CR4.CET is set).
    constexpr u32 kIa32SCet = 0x6A2;
    if (g_cet.cr4_cet_set && (g_cet.ss_supported || g_cet.ibt_supported))
    {
        g_cet.s_cet_value = ReadMsr(kIa32SCet);
    }

    SerialWrite("[cpu] cet: ss=");
    SerialWrite(g_cet.ss_supported ? "supported" : "absent");
    SerialWrite(" ibt=");
    SerialWrite(g_cet.ibt_supported ? "supported" : "absent");
    SerialWrite(" cr4=");
    SerialWrite(g_cet.cr4_cet_set ? "on" : "off");
    SerialWrite("\n");
}

const CetStatus& CetGet()
{
    return g_cet;
}

namespace
{

constexpr u64 kCr4Cet = 1ull << 23;

constexpr u64 kSCetShStkEn = 1ull << 0; // SH_STK_EN
constexpr u64 kSCetWrShStk = 1ull << 1; // WR_SHSTK_EN
// IBT bits are unused under -fcf-protection=none builds (the current
// default; see the DUETOS_KERNEL_HAS_ENDBR-gated branch below). Keep
// them in source as canonical MSR bit-position references.
[[maybe_unused]] constexpr u64 kSCetEndbrEn = 1ull << 2; // ENDBR_EN
[[maybe_unused]] constexpr u64 kSCetNoTrack = 1ull << 4; // NO_TRACK_EN

// Use the kernel-wide ReadCr4 from arch/cpu.h — a local copy
// here would shadow the namespace version and cause an
// ambiguous call when the probe reads CR4. WriteCr4 isn't in
// cpu.h yet so we keep that one local for now.
using ::duetos::arch::ReadCr4;

void WriteCr4(u64 v)
{
    asm volatile("mov %0, %%cr4" : : "r"(v));
}

} // namespace

void CetEnable(u64 kernel_ssp_top)
{
    if (!g_done)
    {
        CetProbe();
    }

    /* No-op if neither CET-SS nor CET-IBT is in silicon. The probe
     * has logged that fact; nothing else to do. */
    if (!g_cet.ss_supported && !g_cet.ibt_supported)
    {
        return;
    }

    /* CR4.CET gates whether the CPU consults IA32_S_CET / IA32_U_CET
     * at all. Set it before writing the MSRs so the writes take
     * effect immediately. */
    WriteCr4(ReadCr4() | kCr4Cet);

    u64 s_cet = 0;
    u64 u_cet = 0;

    if (g_cet.ss_supported)
    {
        s_cet |= kSCetShStkEn | kSCetWrShStk;
        u_cet |= kSCetShStkEn | kSCetWrShStk;
    }
    if (g_cet.ibt_supported)
    {
#if defined(DUETOS_KERNEL_HAS_ENDBR)
        // Build was compiled with -fcf-protection=branch, so every
        // indirect-branch target has an ENDBR64 prologue. Safe to
        // set ENDBR_EN — the CPU will accept all our indirect
        // branches and #CP only on attacker-controlled redirects.
        s_cet |= kSCetEndbrEn | kSCetNoTrack;
        u_cet |= kSCetEndbrEn | kSCetNoTrack;
#else
        // Kernel was built with -fcf-protection=none (the current
        // default — see cmake/toolchains/x86_64-kernel.cmake's GAP
        // note about the KVM emulator bug). Setting ENDBR_EN here
        // would #CP on the very next indirect call. Skip the IBT
        // half of CET; SS (shadow stack) is still safe because it
        // doesn't fault on missing prologues.
        SerialWrite("[cpu] cet: skipping IBT enable — kernel not built with "
                    "-fcf-protection=branch (DUETOS_KERNEL_HAS_ENDBR undef)\n");
#endif
    }

    CetEnableMsrs(s_cet, u_cet);

    if (g_cet.ss_supported && kernel_ssp_top != 0)
    {
        CetSetPl0Ssp(kernel_ssp_top);
    }

    g_cet.ss_enabled = g_cet.ss_supported;
#if defined(DUETOS_KERNEL_HAS_ENDBR)
    g_cet.ibt_enabled = g_cet.ibt_supported;
#else
    g_cet.ibt_enabled = false;
#endif

    SerialWrite("[cpu] cet: enabled (ss=");
    SerialWrite(g_cet.ss_enabled ? "y" : "n");
    SerialWrite(" ibt=");
    SerialWrite(g_cet.ibt_enabled ? "y" : "n");
    SerialWrite(")\n");
}

} // namespace duetos::arch
