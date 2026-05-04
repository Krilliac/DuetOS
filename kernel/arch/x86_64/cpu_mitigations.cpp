/*
 * DuetOS — CPU silicon-level mitigation probe (E2-followup).
 *
 * See `cpu_mitigations.h` for the public contract. This TU owns:
 *   - the CPUID leaf 7 sub-leaf 0 EDX[29] check for ARCH_CAPS,
 *   - the RDMSR 0x10A read,
 *   - the bit-by-bit decoding into `needs_X` booleans,
 *   - the boot-log summary.
 *
 * Defensive on every step: a CPU that doesn't advertise the MSR
 * keeps the conservative defaults (every needs_X = true), and
 * the probe never panics — false negatives in either direction
 * are recoverable, but a panic during early boot for a
 * mitigation probe would be untriagable on the kind of older
 * hardware this code is here to support.
 */

#include "arch/x86_64/cpu_mitigations.h"

#include "arch/x86_64/serial.h"

namespace duetos::arch
{

namespace
{

CpuMitigations g_mit = {};
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

u64 DoRdmsr(u32 msr)
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return (static_cast<u64>(hi) << 32) | static_cast<u64>(lo);
}

constexpr u32 kIa32ArchCapabilities = 0x10A;

// Bits within IA32_ARCH_CAPABILITIES (Intel SDM Vol. 4).
constexpr u64 kArchCapRdclNo = 1ULL << 0;
constexpr u64 kArchCapMdsNo = 1ULL << 5;
constexpr u64 kArchCapSsbNo = 1ULL << 4;
constexpr u64 kArchCapTaaNo = 1ULL << 8;

void Log(const char* tag, bool needs)
{
    SerialWrite(tag);
    SerialWrite(needs ? "=needed" : "=safe");
}

} // namespace

void CpuMitigationsProbe()
{
    if (g_done)
    {
        return;
    }
    g_done = true;

    // Check the highest standard CPUID leaf first — leaf 7 only
    // exists if leaf 0 says so. On an ancient CPU that doesn't
    // expose leaf 7 at all, treat the situation the same as
    // "MSR not present": every needs_X stays true (conservative).
    Cpuid r0 = DoCpuid(0);
    if (r0.eax < 7)
    {
        g_mit.needs_kpti = true;
        g_mit.needs_mds_buf = true;
        g_mit.needs_ssbd = true;
        g_mit.needs_taa_flush = true;
        SerialWrite("[cpu] mitigations: ARCH_CAPS msr unavailable (leaf 7 missing); ");
        SerialWrite("assuming all software mitigations needed.\n");
        return;
    }

    // Leaf 7 sub-leaf 0, EDX bit 29 = "IA32_ARCH_CAPABILITIES MSR
    // is supported". Bit 26 (IBRS_PRED) and bit 27 (STIBP) live
    // nearby but aren't read here — those drive Spectre-v2 work
    // that's out of scope for this slice.
    Cpuid r7 = DoCpuid(7, 0);
    if (((r7.edx >> 29) & 1u) == 0u)
    {
        g_mit.needs_kpti = true;
        g_mit.needs_mds_buf = true;
        g_mit.needs_ssbd = true;
        g_mit.needs_taa_flush = true;
        SerialWrite("[cpu] mitigations: ARCH_CAPS msr unsupported (cpuid 7:0 EDX[29]=0); ");
        SerialWrite("assuming all software mitigations needed.\n");
        return;
    }

    g_mit.arch_capabilities_msr_present = true;
    g_mit.arch_capabilities = DoRdmsr(kIa32ArchCapabilities);

    // Each MSR bit encodes "the CPU is intrinsically safe for
    // this attack class"; needs_X is the negation.
    g_mit.needs_kpti = ((g_mit.arch_capabilities & kArchCapRdclNo) == 0);
    g_mit.needs_mds_buf = ((g_mit.arch_capabilities & kArchCapMdsNo) == 0);
    g_mit.needs_ssbd = ((g_mit.arch_capabilities & kArchCapSsbNo) == 0);
    g_mit.needs_taa_flush = ((g_mit.arch_capabilities & kArchCapTaaNo) == 0);

    // Compact one-line summary, matching the cpu_info.cpp boot-
    // log style. Anything beyond this is for `inspect cpu` (out
    // of scope here).
    SerialWrite("[cpu] mitigations: ARCH_CAPS=");
    SerialWriteHex(g_mit.arch_capabilities);
    SerialWrite(" ");
    Log("kpti", g_mit.needs_kpti);
    SerialWrite(" ");
    Log("mds", g_mit.needs_mds_buf);
    SerialWrite(" ");
    Log("ssbd", g_mit.needs_ssbd);
    SerialWrite(" ");
    Log("taa", g_mit.needs_taa_flush);
    SerialWrite("\n");

    // High-visibility WARN block when the silicon is Meltdown-
    // vulnerable. KPTI is deliberately NOT implemented (see
    // wiki/security/WX-Enforcement.md and wiki/reference/Roadmap.md
    // for the settled decision + trigger conditions); the user
    // should at minimum know that this kernel does not mitigate
    // the attack.
    // Serial-only, deliberately — EventRing is not yet up at the
    // point CpuMitigationsProbe runs.
    if (g_mit.needs_kpti)
    {
        SerialWrite("[cpu] WARN ============================================================\n");
        SerialWrite("[cpu] WARN Meltdown silicon-bit RDCL_NO=0: this CPU IS vulnerable.\n");
        SerialWrite("[cpu] WARN This kernel does NOT implement KPTI (Kernel Page Table\n");
        SerialWrite("[cpu] WARN Isolation). Untrusted ring-3 code can speculatively read\n");
        SerialWrite("[cpu] WARN kernel memory via cache side channel. Do not run\n");
        SerialWrite("[cpu] WARN untrusted PE/ELF binaries on this hardware.\n");
        SerialWrite("[cpu] WARN See wiki/security/WX-Enforcement.md for context.\n");
        SerialWrite("[cpu] WARN ============================================================\n");
    }
}

const CpuMitigations& CpuMitigationsGet()
{
    return g_mit;
}

} // namespace duetos::arch
