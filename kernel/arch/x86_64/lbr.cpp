#include "arch/x86_64/lbr.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"

/*
 * Architectural Last-Branch-Record support — see lbr.h for rationale.
 * MSR addresses + CPUID bit per Intel SDM Vol. 4 §17.10 (cross-checked
 * against Linux's arch/x86/include/asm/msr-index.h).
 */

namespace duetos::arch
{

namespace
{

// CPUID 7.0 EDX[19] — Architectural LBR support. Same bit number
// as Linux's X86_FEATURE_ARCH_LBR.
constexpr u32 kCpuidLeaf7Edx_ArchLbr = 1U << 19;

// Architectural LBR MSRs.
constexpr u32 kMsrArchLbrCtl = 0x14CE;
constexpr u32 kMsrArchLbrDepth = 0x14CF;
constexpr u32 kMsrArchLbrFromBase = 0x1500;
constexpr u32 kMsrArchLbrToBase = 0x1600;
constexpr u32 kMsrArchLbrInfoBase = 0x1200;

// IA32_LBR_CTL bits.
constexpr u64 kLbrCtl_LbrEn = 1ULL << 0;
constexpr u64 kLbrCtl_OS = 1ULL << 1;
constexpr u64 kLbrCtl_USR = 1ULL << 2;

// Set once by LbrInitBsp on success. Read-mostly; no SMP fanout in
// v0 (BSP only).
constinit bool g_lbr_available = false;
constinit u32 g_lbr_depth = 0;

inline void Cpuid(u32 leaf, u32 sub, u32& eax, u32& ebx, u32& ecx, u32& edx)
{
    u32 a = leaf;
    u32 c = sub;
    u32 b = 0;
    u32 d = 0;
    asm volatile("cpuid" : "+a"(a), "+c"(c), "=b"(b), "=d"(d));
    eax = a;
    ebx = b;
    ecx = c;
    edx = d;
}

bool DetectArchLbr()
{
    u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    Cpuid(7, 0, eax, ebx, ecx, edx);
    return (edx & kCpuidLeaf7Edx_ArchLbr) != 0;
}

} // namespace

bool LbrInitBsp()
{
    if (g_lbr_available)
    {
        return true; // idempotent
    }
    if (!DetectArchLbr())
    {
        SerialWrite("[lbr] Architectural LBR unsupported (CPUID 7.0 EDX[19] = 0)\n");
        return false;
    }

    // Probe the maximum supported depth. RDMSR on a CPU that claims
    // ARCH_LBR but actually has it MSR-disabled (hypervisor mask)
    // would #GP — we don't have an extable here yet, so trust the
    // CPUID bit. Real silicon honours it.
    const u64 max_depth = ReadMsr(kMsrArchLbrDepth);
    if (max_depth == 0 || max_depth > kLbrMaxEntries)
    {
        SerialWrite("[lbr] depth out of range — disabling\n");
        return false;
    }

    // Program the desired depth (writing DEPTH selects how many
    // entries are usable; MUST be one of the values reported by
    // CPUID 0x1C.EAX[7:0], but the max read above is always valid).
    WriteMsr(kMsrArchLbrDepth, max_depth);

    // Enable LBR for both ring-0 and ring-3, no filter — every
    // taken branch ends up in the stack. Filtering away ring-3 in
    // the future (when ring-3 traffic dwarfs the kernel signal we
    // care about for panic dumps) is a one-bit flip here.
    const u64 ctl = kLbrCtl_LbrEn | kLbrCtl_OS | kLbrCtl_USR;
    WriteMsr(kMsrArchLbrCtl, ctl);

    g_lbr_depth = static_cast<u32>(max_depth);
    g_lbr_available = true;

    SerialWrite("[lbr] Architectural LBR enabled (depth=");
    SerialWriteHex(max_depth);
    SerialWrite(")\n");
    return true;
}

bool LbrAvailable()
{
    return g_lbr_available;
}

void LbrFreeze()
{
    if (!g_lbr_available)
    {
        return;
    }
    const u64 ctl = ReadMsr(kMsrArchLbrCtl);
    if ((ctl & kLbrCtl_LbrEn) == 0)
    {
        return; // already frozen
    }
    WriteMsr(kMsrArchLbrCtl, ctl & ~kLbrCtl_LbrEn);
}

void LbrCapture(LbrSnapshot& out)
{
    out.depth = 0;
    out.ctl_at_capture = 0;
    for (u32 i = 0; i < kLbrMaxEntries; ++i)
    {
        out.from[i] = 0;
        out.to[i] = 0;
        out.info[i] = 0;
    }
    if (!g_lbr_available)
    {
        return;
    }
    out.ctl_at_capture = ReadMsr(kMsrArchLbrCtl);
    const u32 depth = g_lbr_depth;
    out.depth = depth;
    for (u32 i = 0; i < depth; ++i)
    {
        out.from[i] = ReadMsr(kMsrArchLbrFromBase + i);
        out.to[i] = ReadMsr(kMsrArchLbrToBase + i);
        out.info[i] = ReadMsr(kMsrArchLbrInfoBase + i);
    }
}

} // namespace duetos::arch
