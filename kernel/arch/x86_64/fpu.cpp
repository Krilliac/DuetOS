/*
 * DuetOS — FPU / SSE / AVX init.
 *
 * Probes CPUID, enables OSFXSR / OSXMMEXCPT, optionally enables
 * OSXSAVE + writes XCR0, and caches the save-area size + feature
 * mask for the scheduler to consume. The actual save / restore
 * instructions live in fpu_context.S; this file only owns the
 * init-time CR4 / XCR0 dance and the cached metadata.
 */

#include "arch/x86_64/fpu.h"

#include "arch/x86_64/serial.h"

namespace duetos::arch
{

namespace
{

constexpr u64 kCr4Osfxsr = 1u << 9;      // SSE save/restore via FXSAVE/FXRSTOR
constexpr u64 kCr4OsXmmExcpt = 1u << 10; // SSE-derived #XF dispatch
constexpr u64 kCr4OsXsave = 1u << 18;    // XSAVE / XGETBV / XSETBV legal

constexpr u64 kXFeatureFp = 1u << 0;  // x87 (always set on XSAVE-capable CPUs)
constexpr u64 kXFeatureSse = 1u << 1; // XMM
constexpr u64 kXFeatureAvx = 1u << 2; // YMM (depends on SSE)

bool g_init_done = false;
bool g_xsave_enabled = false;
u32 g_save_area_size = 512; // legacy FXSAVE fallback
u64 g_feature_mask = 0;

struct CpuidRegs
{
    u32 eax, ebx, ecx, edx;
};

CpuidRegs DoCpuid(u32 leaf, u32 subleaf = 0)
{
    CpuidRegs r;
    asm volatile("cpuid" : "=a"(r.eax), "=b"(r.ebx), "=c"(r.ecx), "=d"(r.edx) : "a"(leaf), "c"(subleaf));
    return r;
}

u64 ReadCr4()
{
    u64 v;
    asm volatile("mov %%cr4, %0" : "=r"(v));
    return v;
}

void WriteCr4(u64 v)
{
    asm volatile("mov %0, %%cr4" : : "r"(v));
}

void WriteXcr0(u64 v)
{
    const u32 lo = static_cast<u32>(v);
    const u32 hi = static_cast<u32>(v >> 32);
    /* xsetbv: XCR# selected by ECX. XCR0 is index 0. */
    asm volatile("xsetbv" : : "c"(0u), "a"(lo), "d"(hi));
}

} // namespace

void FpuInit()
{
    if (g_init_done)
    {
        return;
    }
    g_init_done = true;

    const CpuidRegs leaf1 = DoCpuid(1);
    const bool has_fxsr = (leaf1.edx & (1u << 24)) != 0;
    const bool has_sse = (leaf1.edx & (1u << 25)) != 0;
    const bool has_xsave = (leaf1.ecx & (1u << 26)) != 0;
    const bool has_avx = (leaf1.ecx & (1u << 28)) != 0;

    /* OSFXSR + OSXMMEXCPT are required to use FXSAVE / FXRSTOR and
     * to receive #XF for SSE-numerical exceptions. Both are safe
     * to set unconditionally on any long-mode CPU — long mode
     * implies FXSR. */
    u64 cr4 = ReadCr4();
    if (has_fxsr)
    {
        cr4 |= kCr4Osfxsr;
    }
    if (has_sse)
    {
        cr4 |= kCr4OsXmmExcpt;
    }

    if (has_xsave)
    {
        cr4 |= kCr4OsXsave;
        WriteCr4(cr4);

        /* Select the components we want user-mode to be able to
         * use. x87 + SSE always; AVX if the silicon supports it.
         * Future slices add AVX-512 (bits 5..7) behind the same
         * probe + XCR0 bit. */
        u64 mask = kXFeatureFp | kXFeatureSse;
        if (has_avx)
        {
            mask |= kXFeatureAvx;
        }
        WriteXcr0(mask);
        g_feature_mask = mask;

        /* CPUID(0Dh,0).ECX = max size of the XSAVE area for ALL
         * components the CPU supports. We bound the per-task
         * allocation to that number; a future slice that disables
         * AVX at runtime would shrink the live mask but would still
         * size the area at the architectural max so XRSTOR can
         * tolerate a re-enable. */
        const CpuidRegs xs = DoCpuid(0xDu, 0u);
        g_save_area_size = xs.ecx ? xs.ecx : 512u;
        g_xsave_enabled = true;
    }
    else
    {
        WriteCr4(cr4);
        g_feature_mask = 0;
        g_save_area_size = 512;
        g_xsave_enabled = false;
    }

    SerialWrite("[cpu] fpu: fxsr=");
    SerialWrite(has_fxsr ? "y" : "n");
    SerialWrite(" sse=");
    SerialWrite(has_sse ? "y" : "n");
    SerialWrite(" xsave=");
    SerialWrite(g_xsave_enabled ? "y" : "n");
    SerialWrite(" avx=");
    SerialWrite((g_xsave_enabled && has_avx) ? "y" : "n");
    SerialWrite("\n");
}

u32 FpuSaveAreaSize()
{
    return g_save_area_size;
}

u64 FpuXFeatureMask()
{
    return g_feature_mask;
}

bool FpuHasXsave()
{
    return g_xsave_enabled;
}

} // namespace duetos::arch
