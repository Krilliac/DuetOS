#include "arch/x86_64/cpu_info.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "core/panic.h"

namespace duetos::arch
{

namespace
{

CpuInfo g_info = {};

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

void StoreBit(CpuFeature f, bool set)
{
    if (set)
        g_info.feature_bits |= (1u << f);
}

struct FeatureBitTag
{
    CpuFeature feat;
    const char* name;
};

constexpr FeatureBitTag kFeatures[] = {
    {kCpuFeatFpu, "fpu"},        {kCpuFeatTsc, "tsc"},         {kCpuFeatMsr, "msr"},
    {kCpuFeatApic, "apic"},      {kCpuFeatMmx, "mmx"},         {kCpuFeatSse, "sse"},
    {kCpuFeatSse2, "sse2"},      {kCpuFeatSse3, "sse3"},       {kCpuFeatSsse3, "ssse3"},
    {kCpuFeatSse4_1, "sse4.1"},  {kCpuFeatSse4_2, "sse4.2"},   {kCpuFeatAesNi, "aes"},
    {kCpuFeatAvx, "avx"},        {kCpuFeatF16c, "f16c"},       {kCpuFeatRdrand, "rdrand"},
    {kCpuFeatSmep, "smep"},      {kCpuFeatSmap, "smap"},       {kCpuFeatBmi1, "bmi1"},
    {kCpuFeatBmi2, "bmi2"},      {kCpuFeatAvx2, "avx2"},       {kCpuFeatAvx512f, "avx512f"},
    {kCpuFeatRdseed, "rdseed"},  {kCpuFeatNx, "nx"},           {kCpuFeatPdpe1Gb, "1g"},
    {kCpuFeatLongMode, "lm"},    {kCpuFeatX2Apic, "x2apic"},   {kCpuFeatTscDeadline, "tscdl"},
    {kCpuFeatHypervisor, "hyp"}, {kCpuFeatMonitor, "monitor"},
};

// Pack 4 bytes of a u32 register into a char buffer (little-endian
// AAAA order). Used for vendor / brand string reconstruction.
void PackReg(char* dst, u32 reg)
{
    dst[0] = char(reg & 0xFF);
    dst[1] = char((reg >> 8) & 0xFF);
    dst[2] = char((reg >> 16) & 0xFF);
    dst[3] = char((reg >> 24) & 0xFF);
}

} // namespace

void CpuInfoProbe()
{
    static constinit bool s_done = false;
    KASSERT(!s_done, "arch/cpu", "CpuInfoProbe called twice");
    s_done = true;

    // Leaf 0: vendor string in ebx:edx:ecx (non-obvious order).
    Cpuid r0 = DoCpuid(0);
    PackReg(g_info.vendor + 0, r0.ebx);
    PackReg(g_info.vendor + 4, r0.edx);
    PackReg(g_info.vendor + 8, r0.ecx);
    g_info.vendor[12] = '\0';

    // Leaf 1: family/model/stepping + features.
    Cpuid r1 = DoCpuid(1);
    const u32 base_family = (r1.eax >> 8) & 0xF;
    const u32 ext_family = (r1.eax >> 20) & 0xFF;
    const u32 base_model = (r1.eax >> 4) & 0xF;
    const u32 ext_model = (r1.eax >> 16) & 0xF;
    g_info.family = (base_family == 0xF) ? (base_family + ext_family) : base_family;
    g_info.model = (base_family == 0x6 || base_family == 0xF) ? ((ext_model << 4) | base_model) : base_model;
    g_info.stepping = r1.eax & 0xF;
    g_info.logical_cpus = (r1.ebx >> 16) & 0xFF;

    // ECX bits we care about:
    //  0=SSE3, 9=SSSE3, 19=SSE4.1, 20=SSE4.2, 21=x2APIC,
    //  24=TSC-Deadline, 25=AES, 28=AVX, 29=F16C, 30=RDRAND,
    //  31=Hypervisor-present.
    StoreBit(kCpuFeatSse3, (r1.ecx >> 0) & 1);
    StoreBit(kCpuFeatSsse3, (r1.ecx >> 9) & 1);
    StoreBit(kCpuFeatSse4_1, (r1.ecx >> 19) & 1);
    StoreBit(kCpuFeatSse4_2, (r1.ecx >> 20) & 1);
    StoreBit(kCpuFeatMonitor, (r1.ecx >> 3) & 1);
    StoreBit(kCpuFeatX2Apic, (r1.ecx >> 21) & 1);
    StoreBit(kCpuFeatTscDeadline, (r1.ecx >> 24) & 1);
    StoreBit(kCpuFeatAesNi, (r1.ecx >> 25) & 1);
    StoreBit(kCpuFeatAvx, (r1.ecx >> 28) & 1);
    StoreBit(kCpuFeatF16c, (r1.ecx >> 29) & 1);
    StoreBit(kCpuFeatRdrand, (r1.ecx >> 30) & 1);
    StoreBit(kCpuFeatHypervisor, (r1.ecx >> 31) & 1);

    // EDX bits: 0=FPU, 4=TSC, 5=MSR, 6=PAE, 9=APIC, 11=SEP,
    //           23=MMX, 25=SSE, 26=SSE2.
    StoreBit(kCpuFeatFpu, (r1.edx >> 0) & 1);
    StoreBit(kCpuFeatTsc, (r1.edx >> 4) & 1);
    StoreBit(kCpuFeatMsr, (r1.edx >> 5) & 1);
    StoreBit(kCpuFeatPae, (r1.edx >> 6) & 1);
    StoreBit(kCpuFeatApic, (r1.edx >> 9) & 1);
    StoreBit(kCpuFeatSep, (r1.edx >> 11) & 1);
    StoreBit(kCpuFeatMmx, (r1.edx >> 23) & 1);
    StoreBit(kCpuFeatSse, (r1.edx >> 25) & 1);
    StoreBit(kCpuFeatSse2, (r1.edx >> 26) & 1);

    // Leaf 7, sub-leaf 0. EBX bits: 3=BMI1, 7=SMEP, 8=BMI2,
    //   5=AVX2, 16=AVX-512F, 18=RDSEED, 20=SMAP.
    if (r0.eax >= 7)
    {
        Cpuid r7 = DoCpuid(7, 0);
        StoreBit(kCpuFeatBmi1, (r7.ebx >> 3) & 1);
        StoreBit(kCpuFeatAvx2, (r7.ebx >> 5) & 1);
        StoreBit(kCpuFeatSmep, (r7.ebx >> 7) & 1);
        StoreBit(kCpuFeatBmi2, (r7.ebx >> 8) & 1);
        StoreBit(kCpuFeatAvx512f, (r7.ebx >> 16) & 1);
        StoreBit(kCpuFeatRdseed, (r7.ebx >> 18) & 1);
        StoreBit(kCpuFeatSmap, (r7.ebx >> 20) & 1);
    }

    // Leaf 0x80000001 EDX bits: 20=NX/XD, 26=1G-pages, 29=Long-Mode.
    // The whole leaf-range is gated on `r80.eax >= 0x80000001` so a
    // CPU that doesn't even expose extended leaves leaves these
    // feature bits clear (and the minimum-feature gate flags the
    // missing NX as a hard-stop).
    Cpuid r80 = DoCpuid(0x80000000);
    if (r80.eax >= 0x80000001)
    {
        Cpuid r81 = DoCpuid(0x80000001);
        StoreBit(kCpuFeatNx, (r81.edx >> 20) & 1);
        StoreBit(kCpuFeatPdpe1Gb, (r81.edx >> 26) & 1);
        StoreBit(kCpuFeatLongMode, (r81.edx >> 29) & 1);
    }

    // Leaves 0x80000002/3/4: brand string (48 chars + NUL). Not
    // all CPUs expose it; check max extended leaf first.
    if (r80.eax >= 0x80000004)
    {
        Cpuid a = DoCpuid(0x80000002);
        Cpuid b = DoCpuid(0x80000003);
        Cpuid c = DoCpuid(0x80000004);
        PackReg(g_info.brand + 0, a.eax);
        PackReg(g_info.brand + 4, a.ebx);
        PackReg(g_info.brand + 8, a.ecx);
        PackReg(g_info.brand + 12, a.edx);
        PackReg(g_info.brand + 16, b.eax);
        PackReg(g_info.brand + 20, b.ebx);
        PackReg(g_info.brand + 24, b.ecx);
        PackReg(g_info.brand + 28, b.edx);
        PackReg(g_info.brand + 32, c.eax);
        PackReg(g_info.brand + 36, c.ebx);
        PackReg(g_info.brand + 40, c.ecx);
        PackReg(g_info.brand + 44, c.edx);
        g_info.brand[48] = '\0';
    }
    else
    {
        g_info.brand[0] = '\0';
    }

    g_info.valid = true;

    // Log a compact summary. Brand string is the headline; family/
    // model/stepping + enabled feature tags follow.
    SerialWrite("[cpu] vendor=\"");
    SerialWrite(g_info.vendor);
    SerialWrite("\" brand=\"");
    SerialWrite(g_info.brand);
    SerialWrite("\"\n");
    SerialWrite("[cpu] family=");
    SerialWriteHex(g_info.family);
    SerialWrite(" model=");
    SerialWriteHex(g_info.model);
    SerialWrite(" stepping=");
    SerialWriteHex(g_info.stepping);
    SerialWrite(" logical_cpus=");
    SerialWriteHex(g_info.logical_cpus);
    SerialWrite("\n");
    SerialWrite("[cpu] features:");
    for (const FeatureBitTag& f : kFeatures)
    {
        if (CpuHas(f.feat))
        {
            SerialWrite(" ");
            SerialWrite(f.name);
        }
    }
    SerialWrite("\n");
}

const CpuInfo& CpuInfoGet()
{
    return g_info;
}

bool CpuHas(CpuFeature feat)
{
    if (!g_info.valid)
        return false;
    if (u32(feat) >= u32(kCpuFeatCount))
        return false;
    return (g_info.feature_bits & (1u << feat)) != 0;
}

[[noreturn]] void CpuMinimumFeatureGateFail(const char* missing)
{
    // Use raw serial because the panic system relies on serial
    // already, and we want the same single-line marker visible whether
    // the operator is reading via QEMU `-serial stdio` or a real COM1
    // pin-out. The line shape is grep-friendly:
    //     [cpu] HARD STOP: CPU baseline unmet — missing: <feature> ...
    SerialWrite("\n[cpu] HARD STOP: CPU baseline unmet — missing:");
    SerialWrite(missing);
    SerialWrite("\n[cpu] DuetOS requires an x86_64 CPU advertising at minimum:\n");
    SerialWrite("[cpu]   FPU MMX SSE SSE2 TSC MSR APIC PAE NX LongMode\n");
    SerialWrite("[cpu] The probed CPUID feature word was incomplete; halting.\n");
    core::Panic("arch/cpu", "minimum CPU feature baseline unmet");
}

void CpuMinimumFeatureGate()
{
    // We deliberately use a tight chain of explicit checks instead of
    // a table loop. The point of this gate is "halt with a clear
    // message naming the missing feature" — a table would force a
    // generic "missing feature #N" log line that an operator on real
    // hardware would have to cross-reference manually.
    if (!CpuHas(kCpuFeatFpu))
        CpuMinimumFeatureGateFail(" FPU");
    if (!CpuHas(kCpuFeatMmx))
        CpuMinimumFeatureGateFail(" MMX");
    if (!CpuHas(kCpuFeatSse))
        CpuMinimumFeatureGateFail(" SSE");
    if (!CpuHas(kCpuFeatSse2))
        CpuMinimumFeatureGateFail(" SSE2");
    if (!CpuHas(kCpuFeatTsc))
        CpuMinimumFeatureGateFail(" TSC");
    if (!CpuHas(kCpuFeatMsr))
        CpuMinimumFeatureGateFail(" MSR");
    if (!CpuHas(kCpuFeatApic))
        CpuMinimumFeatureGateFail(" APIC");
    if (!CpuHas(kCpuFeatPae))
        CpuMinimumFeatureGateFail(" PAE");
    // NX is the critical one: paging.cpp unconditionally sets
    // EFER.NXE, which #GPs on a CPU that doesn't advertise NX.
    // Without this gate, that #GP fires from an early-init context
    // where the trap path may not yet be fully set up — and the
    // result is a silent triple-fault instead of a readable banner.
    if (!CpuHas(kCpuFeatNx))
        CpuMinimumFeatureGateFail(" NX");
    if (!CpuHas(kCpuFeatLongMode))
        CpuMinimumFeatureGateFail(" LongMode");

    SerialWrite("[cpu] minimum-feature gate OK (FPU MMX SSE SSE2 TSC MSR APIC PAE NX LongMode all present)\n");

    // Advisory log of optional-but-impactful features that the
    // kernel adapts around at the call sites. Naming them here gives
    // the operator a single line to scan when triaging "why is
    // feature X behaving differently on this box?".
    SerialWrite("[cpu] optional:");
    if (CpuHas(kCpuFeatSmep))
        SerialWrite(" smep");
    if (CpuHas(kCpuFeatSmap))
        SerialWrite(" smap");
    if (CpuHas(kCpuFeatPdpe1Gb))
        SerialWrite(" 1g");
    if (CpuHas(kCpuFeatX2Apic))
        SerialWrite(" x2apic");
    if (CpuHas(kCpuFeatTscDeadline))
        SerialWrite(" tscdl");
    if (CpuHas(kCpuFeatRdrand))
        SerialWrite(" rdrand");
    if (CpuHas(kCpuFeatRdseed))
        SerialWrite(" rdseed");
    if (CpuHas(kCpuFeatAesNi))
        SerialWrite(" aes");
    if (CpuHas(kCpuFeatHypervisor))
        SerialWrite(" hyp");
    SerialWrite("\n");
}

} // namespace duetos::arch
