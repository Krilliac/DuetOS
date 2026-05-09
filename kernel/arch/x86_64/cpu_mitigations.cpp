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
constexpr u64 kArchCapIbrsAll = 1ULL << 1; // Enhanced IBRS — HW always-on Spec-v2 mitigation
constexpr u64 kArchCapMdsNo = 1ULL << 5;
constexpr u64 kArchCapSsbNo = 1ULL << 4;
constexpr u64 kArchCapTaaNo = 1ULL << 8;

// CPUID 7:0 EDX bits — Spec-v2 software-mitigation feature flags.
constexpr u32 kCpuidEdxIbrs = 1u << 26;  // IA32_SPEC_CTRL.IBRS available
constexpr u32 kCpuidEdxStibp = 1u << 27; // STIBP available

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
    // is supported". Bits 26 / 27 in the same register tell us
    // whether the CPU has the IBRS / STIBP machinery for Spec-v2
    // work — read both alongside the ARCH_CAPS gate so a single
    // probe pass populates the full Spec-v2 picture.
    Cpuid r7 = DoCpuid(7, 0);
    g_mit.has_ibrs = (r7.edx & kCpuidEdxIbrs) != 0;
    g_mit.has_stibp = (r7.edx & kCpuidEdxStibp) != 0;

    if (((r7.edx >> 29) & 1u) == 0u)
    {
        g_mit.needs_kpti = true;
        g_mit.needs_mds_buf = true;
        g_mit.needs_ssbd = true;
        g_mit.needs_taa_flush = true;
        // Without ARCH_CAPS we can't read IBRS_ALL, so we don't
        // know whether the silicon is Enhanced-IBRS-capable. The
        // safe answer is "retpolines are doing useful work".
        g_mit.needs_retpolines = true;
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

    // Enhanced IBRS = IBRS_ALL bit set. When the silicon advertises
    // it, the CPU prevents BTI on indirect branches without
    // software help — retpolines become pure tax. The conservative
    // answer (retpolines needed) is the default; we only flip it
    // off when we have explicit silicon confirmation.
    g_mit.has_eibrs = (g_mit.arch_capabilities & kArchCapIbrsAll) != 0;
    g_mit.needs_retpolines = !g_mit.has_eibrs;

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
    SerialWrite(" ");
    Log("retpoline", g_mit.needs_retpolines);
    SerialWrite(" ibrs=");
    SerialWrite(g_mit.has_ibrs ? "yes" : "no");
    SerialWrite(" eibrs=");
    SerialWrite(g_mit.has_eibrs ? "yes" : "no");
    SerialWrite(" stibp=");
    SerialWrite(g_mit.has_stibp ? "yes" : "no");
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

    // Spec-v2 perf-opportunity surface: this CPU mitigates BTI in
    // hardware (Enhanced IBRS) but the kernel image was still
    // built with software retpolines. Every indirect call pays
    // the retpoline tax for protection the silicon already
    // provides. Surface this as an INFO note — it's not a
    // security regression (the path is over-protected, not
    // under-protected), but it IS a real perf headroom item.
    //
    // Removing the SW tax requires an alternative-patching
    // framework (Linux's `.altinstructions`-equivalent) that can
    // rewrite every `call __x86_indirect_thunk_rax` callsite to a
    // direct `jmp *%rax` at boot. That framework is not yet in
    // tree; this log line is the prerequisite signal — once an
    // operator (or CI profile) wants the perf back, the trigger
    // condition is "needs_retpolines == false on the target
    // fleet's silicon".
    if (!g_mit.needs_retpolines)
    {
        SerialWrite("[cpu] INFO Enhanced IBRS present (ARCH_CAPS.IBRS_ALL=1): this CPU\n");
        SerialWrite("[cpu] INFO mitigates Spectre v2 (BTI) in silicon. The compile-time\n");
        SerialWrite("[cpu] INFO retpoline thunks (-mretpoline) are redundant on this\n");
        SerialWrite("[cpu] INFO hardware — every indirect call pays a tax for protection\n");
        SerialWrite("[cpu] INFO the silicon already provides. Removing the tax needs an\n");
        SerialWrite("[cpu] INFO alternative-patching framework; see roadmap.\n");
    }
    else if (!g_mit.has_eibrs && g_mit.has_ibrs)
    {
        SerialWrite("[cpu] INFO Spectre v2: legacy IBRS available but Enhanced IBRS is\n");
        SerialWrite("[cpu] INFO not. Software retpolines remain the cheapest mitigation\n");
        SerialWrite("[cpu] INFO until per-entry IBRS write paths land.\n");
    }
}

const CpuMitigations& CpuMitigationsGet()
{
    return g_mit;
}

} // namespace duetos::arch
