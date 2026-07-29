#include "arch/x86_64/cpufreq.h"

#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/cpu_sensor_math.h"
#include "arch/x86_64/cpufreq_msr.h"
#include "arch/x86_64/msr_safe.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"

/*
 * DuetOS — CPU P-state CONTROL. The only file in the tree that writes
 * a CPU operating-point MSR.
 *
 * Split out of cpufreq.cpp (which keeps the telemetry read) so that
 * "which code can drive the hardware" is answerable by file name. The
 * full safety contract — the three gates, what is never written, and
 * why there is no syscall — is documented on the declarations in
 * cpufreq.h; read that before changing anything here.
 *
 * The one-line version: no write happens unless the operator booted
 * with `cpufreq=tune`, the caller holds kCapPowerTune (enforced at the
 * caller — `arch` has no view of the process model), and the value sits
 * inside a window read from this part's own registers on this call.
 * Ratios and P-state indices only. Never a voltage.
 *
 * Context: kernel. wrmsr in ring 0, through the extable-guarded
 * WriteMsrSafe so a #GP on an unimplemented MSR is recovered.
 */

namespace duetos::arch
{

namespace
{

namespace csm = ::duetos::arch::cpu_sensor_math;
namespace msr = ::duetos::arch::cpufreq_msr;

// Operator unlock. Default false, so a boot that does not carry
// `cpufreq=tune` cannot write a P-state MSR no matter what else it
// holds. This is the outermost of the three gates.
constinit bool g_tune_enabled = false;

// Which control registers answered, resolved on first use and then
// believed. Caching is not an optimisation: a declined read costs a
// full trap plus one `[extable] recovered kernel trap` line, and the
// shell's `cpufreq` command reads the caps on every invocation.
//
// What is cached is AVAILABILITY, never a VALUE — the window and the
// current operating point are re-read every call, so a stale cached
// window can never be the thing a request is admitted against.
//
// Deliberately separate from cpufreq.cpp's telemetry cache: the two
// halves probe different register sets, and sharing one cache would
// make either half's probe results silently authoritative for the
// other.
struct CtlAvail
{
    bool resolved;
    bool platform_info; // Intel IA32_PLATFORM_INFO (legacy window floor)
    bool perf_status;   // Intel IA32_PERF_STATUS (current ratio)
    bool perf_ctl;      // Intel IA32_PERF_CTL
    bool turbo;         // Intel MSR_TURBO_RATIO_LIMIT
    bool hwp_regs;      // HWP enabled AND CAPABILITIES + REQUEST readable
    bool amd_ctl;       // AMD MSR_PSTATE_CTL
};

constinit CtlAvail g_ctl = {};

/// Does this part advertise HWP, and has firmware already turned it on?
///
/// We deliberately do NOT enable HWP ourselves. IA32_PM_ENABLE bit 0 is
/// write-once until reset, and switching the platform into
/// hardware-managed P-states changes the behaviour of the whole machine,
/// not just the operating point we were asked to set — a much larger
/// commitment than this surface was approved for. So HWP is used where
/// firmware already chose it (in which case IA32_PERF_CTL is ignored by
/// the part anyway), and the legacy register is used otherwise.
///
/// GAP: on a part where firmware left HWP off the operator gets the
/// legacy PERF_CTL path and no EPP control — revisit together with the
/// EPP / idle-governor work, which needs this same enable decision.
bool HwpActive()
{
    // CPUID.06H:EAX bit 7 — HWP supported.
    if ((msr::Cpuid(6).eax & (1u << 7)) == 0)
        return false;
    u64 pm_enable = 0;
    if (!ReadMsrSafe(msr::kIa32PmEnable, &pm_enable))
        return false;
    return (pm_enable & 0x1u) != 0;
}

void ResolveCtlAvail(bool intel, bool amd)
{
    u64 scratch = 0;
    if (intel)
    {
        if (HwpActive())
        {
            g_ctl.hwp_regs =
                ReadMsrSafe(msr::kIa32HwpCapabilities, &scratch) && ReadMsrSafe(msr::kIa32HwpRequest, &scratch);
        }
        g_ctl.platform_info = ReadMsrSafe(msr::kPlatformInfo, &scratch);
        g_ctl.perf_status = ReadMsrSafe(msr::kIa32PerfStatus, &scratch);
        g_ctl.perf_ctl = ReadMsrSafe(msr::kIa32PerfCtl, &scratch);
        g_ctl.turbo = ReadMsrSafe(msr::kTurboRatioLimit, &scratch);
    }
    else if (amd && csm::ZenFamilySupported(CpuInfoGet().family))
    {
        g_ctl.amd_ctl = ReadMsrSafe(msr::kAmdPstateCtl, &scratch);
    }
    g_ctl.resolved = true;
}

/// Intel HWP window, straight out of IA32_HWP_CAPABILITIES.
bool ControlCapsHwp(CpuFreqControlCaps& caps)
{
    u64 hwp_caps = 0;
    if (!ReadMsrSafe(msr::kIa32HwpCapabilities, &hwp_caps) || hwp_caps == 0)
        return false;
    const u32 lowest = csm::HwpCapLowest(hwp_caps);
    const u32 highest = csm::HwpCapHighest(hwp_caps);
    if (lowest == 0 || highest == 0 || lowest > highest)
        return false;

    caps.mechanism = CpuFreqMechanism::Hwp;
    caps.lowest = lowest;
    caps.highest = highest;
    caps.guaranteed = csm::HwpCapGuaranteed(hwp_caps);
    caps.most_efficient = csm::HwpCapMostEfficient(hwp_caps);

    // Desired == 0 is the architectural "hardware chooses"; report it as
    // unknown rather than as an operating point of zero.
    u64 request = 0;
    if (ReadMsrSafe(msr::kIa32HwpRequest, &request))
        caps.current = csm::HwpRequestDesired(request);
    caps.valid = true;
    return true;
}

/// Intel legacy window: floor from IA32_PLATFORM_INFO's max-efficiency
/// ratio, ceiling from MSR_TURBO_RATIO_LIMIT where the part exposes it,
/// otherwise the max non-turbo ratio. Never a guessed headroom — without
/// the turbo register we simply do not offer turbo ratios.
bool ControlCapsPerfCtl(CpuFreqControlCaps& caps)
{
    u64 info = 0;
    if (!g_ctl.platform_info || !ReadMsrSafe(msr::kPlatformInfo, &info) || info == 0 || info == ~0ULL)
        return false;
    const u32 base_ratio = csm::IntelPlatformInfoBaseRatio(info);
    const u32 min_ratio = csm::IntelPlatformInfoMinRatio(info);
    if (base_ratio == 0 || min_ratio == 0)
        return false;

    u32 ceiling = base_ratio;
    u64 turbo = 0;
    if (g_ctl.turbo && ReadMsrSafe(msr::kTurboRatioLimit, &turbo))
    {
        const u32 turbo_1c = csm::IntelTurboRatioLimit1C(turbo);
        if (turbo_1c > ceiling)
            ceiling = turbo_1c;
    }

    caps.mechanism = CpuFreqMechanism::PerfCtl;
    caps.lowest = min_ratio;
    caps.highest = ceiling;
    // The max non-turbo ratio is this path's "guaranteed": anything
    // above it is turbo the part may or may not sustain. Left as the
    // reference point only — the ceiling above is what admission uses.
    caps.guaranteed = base_ratio;
    u64 perf_status = 0;
    if (g_ctl.perf_status && ReadMsrSafe(msr::kIa32PerfStatus, &perf_status))
        caps.current = csm::IntelPerfStatusRatio(perf_status);
    caps.valid = true;
    return true;
}

/// AMD window: the enabled entries of the platform's own P-state table.
/// A LOWER index is a HIGHER frequency, so `highest` (the
/// highest-performance end) is the numerically smallest enabled index.
bool ControlCapsAmd(CpuFreqControlCaps& caps)
{
    u32 best = msr::kAmdPstateCount; // smallest enabled index seen
    u32 worst = 0;                   // largest enabled index seen
    bool any = false;
    for (u32 i = 0; i < msr::kAmdPstateCount; ++i)
    {
        u64 def = 0;
        if (!ReadMsrSafe(msr::kAmdPstateDef0 + i, &def))
            break;
        if (csm::ZenPstateMhz(def) == 0)
            continue;
        if (!any || i < best)
            best = i;
        if (!any || i > worst)
            worst = i;
        any = true;
    }
    if (!any)
        return false;

    caps.unit_is_ratio = false;
    caps.mechanism = CpuFreqMechanism::AmdPstate;
    caps.highest = best;
    caps.lowest = worst;
    u64 status = 0;
    if (ReadMsrSafe(msr::kAmdPstateStatus, &status))
        caps.current = static_cast<u32>(status & csm::kAmdPstateCtlIndexMask);
    caps.valid = true;
    return true;
}

/// Is `index` one of the P-states the platform actually enabled?
/// Membership of the window is not enough — the table can have holes.
bool AmdPstateEnabled(u32 index)
{
    u64 def = 0;
    if (index >= msr::kAmdPstateCount || !ReadMsrSafe(msr::kAmdPstateDef0 + index, &def))
        return false;
    return csm::ZenPstateMhz(def) != 0;
}

/// One safe write-then-verify against `msr_id`. `composed` is the value
/// to write; `extract` pulls the field back out of the read-back so the
/// write can be checked rather than assumed.
CpuFreqSetStatus WriteVerified(u32 msr_id, u64 composed, u32 want, u32 (*extract)(u64))
{
    if (!WriteMsrSafe(msr_id, composed))
        return CpuFreqSetStatus::WriteFailed;
    u64 readback = 0;
    if (!ReadMsrSafe(msr_id, &readback) || extract(readback) != want)
        return CpuFreqSetStatus::NotVerified;
    return CpuFreqSetStatus::Ok;
}

void LogTransition(const CpuFreqControlCaps& caps, u32 target)
{
    // WARN, not DEBUG: the operating point of the CPU was changed by
    // software. A boot log must show that without anyone having to raise
    // the log level to find out.
    KLOG_WARN("arch/cpufreq", "P-state written (operator tune mode)");
    SerialLineGuard guard;
    SerialWrite("[cpufreq] set mechanism=");
    SerialWrite(CpuFreqMechanismName(caps.mechanism));
    SerialWrite(caps.unit_is_ratio ? " unit=ratio old=" : " unit=pstate_index old=");
    SerialWriteHex(caps.current);
    SerialWrite(" new=");
    SerialWriteHex(target);
    SerialWrite(" window=");
    SerialWriteHex(caps.lowest);
    SerialWrite("..");
    SerialWriteHex(caps.highest);
    SerialWrite("\n");
}

} // namespace

const char* CpuFreqMechanismName(CpuFreqMechanism mechanism)
{
    switch (mechanism)
    {
    case CpuFreqMechanism::Hwp:
        return "hwp";
    case CpuFreqMechanism::PerfCtl:
        return "perf_ctl";
    case CpuFreqMechanism::AmdPstate:
        return "amd_pstate";
    case CpuFreqMechanism::None:
        break;
    }
    return "none";
}

const char* CpuFreqSetStatusName(CpuFreqSetStatus status)
{
    switch (status)
    {
    case CpuFreqSetStatus::Ok:
        return "ok";
    case CpuFreqSetStatus::TuneModeOff:
        return "tune-mode-off (boot with cpufreq=tune)";
    case CpuFreqSetStatus::Unsupported:
        return "unsupported (no writable control interface)";
    case CpuFreqSetStatus::OutOfRange:
        return "out-of-range (outside the platform-advertised window)";
    case CpuFreqSetStatus::WriteFailed:
        return "write-failed (#GP recovered)";
    case CpuFreqSetStatus::NotVerified:
        return "not-verified (read-back disagreed)";
    }
    return "<unknown>";
}

void CpuFreqTuneEnable()
{
    g_tune_enabled = true;
    KLOG_WARN("arch/cpufreq", "P-state tune mode ENABLED (cpufreq=tune) - writes to IA32_PERF_CTL/HWP/PSTATE_CTL "
                              "are now permitted for kCapPowerTune holders");
    SerialWrite("[cpufreq] tune=enabled (P-state writes unlocked)\n");
}

bool CpuFreqTuneEnabled()
{
    return g_tune_enabled;
}

CpuFreqControlCaps CpuFreqControlRead()
{
    CpuFreqControlCaps caps = {};
    caps.unit_is_ratio = true;
    caps.mechanism = CpuFreqMechanism::None;
    if (!CpuHas(kCpuFeatMsr))
        return CpuFreqControlCaps{};

    const bool intel = CpuVendorIsIntel();
    const bool amd = CpuVendorIsAmd();
    if (!intel && !amd)
        return CpuFreqControlCaps{};

    if (!g_ctl.resolved)
        ResolveCtlAvail(intel, amd);

    if (intel)
    {
        // HWP first where firmware enabled it: on such a part
        // IA32_PERF_CTL is ignored, so offering it would be offering a
        // control that does nothing.
        if (g_ctl.hwp_regs && ControlCapsHwp(caps))
            return caps;
        if (g_ctl.perf_ctl && ControlCapsPerfCtl(caps))
            return caps;
        return CpuFreqControlCaps{};
    }

    if (g_ctl.amd_ctl && ControlCapsAmd(caps))
        return caps;
    return CpuFreqControlCaps{};
}

CpuFreqSetStatus CpuFreqSetTarget(u32 target)
{
    // Gate 1 — operator unlock. Checked before anything is even read, so
    // a locked boot leaves no trace of a control attempt on the hardware.
    if (!g_tune_enabled)
        return CpuFreqSetStatus::TuneModeOff;

    // Gate 3 lives here (gate 2, the kCapPowerTune check, is the
    // caller's — see cpufreq.h). The window comes from registers read
    // THIS call, never from a value cached across a resume.
    const CpuFreqControlCaps caps = CpuFreqControlRead();
    if (!caps.valid || caps.mechanism == CpuFreqMechanism::None)
        return CpuFreqSetStatus::Unsupported;

    CpuFreqSetStatus status = CpuFreqSetStatus::Unsupported;
    switch (caps.mechanism)
    {
    case CpuFreqMechanism::Hwp:
    {
        if (csm::RatioAdmit(target, caps.lowest, caps.highest) == 0)
            return CpuFreqSetStatus::OutOfRange;
        u64 request = 0;
        if (!ReadMsrSafe(msr::kIa32HwpRequest, &request))
            return CpuFreqSetStatus::Unsupported;
        // min == max == desired pins the operating point. EPP and the
        // activity window are preserved, not chosen by us.
        const u64 composed = csm::HwpRequestWithPerf(request, target, target, target);
        status = WriteVerified(msr::kIa32HwpRequest, composed, target, csm::HwpRequestDesired);
        break;
    }
    case CpuFreqMechanism::PerfCtl:
    {
        if (csm::RatioAdmit(target, caps.lowest, caps.highest) == 0)
            return CpuFreqSetStatus::OutOfRange;
        u64 perf_ctl = 0;
        if (!ReadMsrSafe(msr::kIa32PerfCtl, &perf_ctl))
            return CpuFreqSetStatus::Unsupported;
        // Bit 32 (IDA/turbo disengage) and every other bit firmware set
        // survive; only the ratio field moves.
        const u64 composed = csm::IntelPerfCtlWithRatio(perf_ctl, target);
        status = WriteVerified(msr::kIa32PerfCtl, composed, target, csm::IntelPerfCtlRatio);
        break;
    }
    case CpuFreqMechanism::AmdPstate:
    {
        // `highest` is the numerically SMALLEST enabled index, so the
        // window test is inverted relative to Intel's ratios. Being in
        // the window is necessary but not sufficient: the table can have
        // disabled entries between the two ends.
        if (target < caps.highest || target > caps.lowest || !AmdPstateEnabled(target))
            return CpuFreqSetStatus::OutOfRange;
        // Only PSTATE_CTL is written. MSR_PSTATE_DEF, which carries
        // CpuVid, is never touched — the voltage that goes with this
        // ratio stays the one AMD's firmware validated.
        status = WriteVerified(msr::kAmdPstateCtl, static_cast<u64>(target & csm::kAmdPstateCtlIndexMask), target,
                               csm::AmdPstateCtlIndex);
        break;
    }
    case CpuFreqMechanism::None:
        return CpuFreqSetStatus::Unsupported;
    }

    if (status == CpuFreqSetStatus::Ok)
        LogTransition(caps, target);
    else
        KLOG_WARN("arch/cpufreq", "P-state write did not take effect");
    return status;
}

void CpuFreqControlSelfTest()
{
    using core::PanicWithValue;

    // The admission window REFUSES rather than clamps, in both
    // directions and on a garbage window. A regression here is a wrong
    // ratio written to real silicon, so it panics like the rest.
    if (csm::RatioAdmit(28, 8, 40) != 28u)
        PanicWithValue("arch/cpufreq", "in-window ratio refused", 1);
    if (csm::RatioAdmit(41, 8, 40) != 0u)
        PanicWithValue("arch/cpufreq", "above-ceiling ratio admitted", 2);
    if (csm::RatioAdmit(7, 8, 40) != 0u)
        PanicWithValue("arch/cpufreq", "below-floor ratio admitted", 3);
    if (csm::RatioAdmit(28, 40, 8) != 0u)
        PanicWithValue("arch/cpufreq", "inverted window admitted a ratio", 4);
    if (csm::RatioAdmit(28, 0, 40) != 0u)
        PanicWithValue("arch/cpufreq", "unread floor admitted a ratio", 5);

    // Read-modify-write must preserve bit 32 (IDA/turbo disengage).
    const u64 spliced = csm::IntelPerfCtlWithRatio((1ULL << 32) | 0x1400ULL, 28);
    if (spliced != ((1ULL << 32) | 0x1C00ULL))
        PanicWithValue("arch/cpufreq", "PERF_CTL splice lost a firmware bit", static_cast<u32>(spliced));

    // HWP splice must preserve EPP (31:24).
    const u64 hwp = csm::HwpRequestWithPerf(0x80ULL << 24, 20, 20, 20);
    if (csm::HwpRequestDesired(hwp) != 20u || ((hwp >> 24) & 0xFFu) != 0x80u)
        PanicWithValue("arch/cpufreq", "HWP splice lost EPP", static_cast<u32>(hwp >> 24));

    // Control-caps honesty: an unsupported window must be entirely
    // empty, and a valid one must name a mechanism and a coherent range.
    // Otherwise a caller that only checks `valid` — or worse, only reads
    // `lowest`/`highest` — admits a request against a window nobody read.
    const CpuFreqControlCaps ctl = CpuFreqControlRead();
    if (!ctl.valid && (ctl.mechanism != CpuFreqMechanism::None || ctl.lowest != 0 || ctl.highest != 0))
        PanicWithValue("arch/cpufreq", "unsupported control caps carry a window", ctl.highest);
    if (ctl.valid && ctl.mechanism == CpuFreqMechanism::None)
        PanicWithValue("arch/cpufreq", "valid control caps name no mechanism", ctl.highest);
    if (ctl.valid && ctl.unit_is_ratio && ctl.lowest > ctl.highest)
        PanicWithValue("arch/cpufreq", "Intel control window inverted", ctl.lowest);
    if (ctl.valid && !ctl.unit_is_ratio && ctl.highest > ctl.lowest)
        PanicWithValue("arch/cpufreq", "AMD P-state index window inverted", ctl.highest);

    // Default-locked invariant: without `cpufreq=tune` NOTHING can write
    // a P-state MSR. Only asserted on a locked boot — on a `cpufreq=tune`
    // boot this call would be a real hardware write, which a self-test
    // has no business performing. Boot order puts this self-test before
    // the cmdline is parsed, so the locked branch is the one CI takes.
    if (!g_tune_enabled && CpuFreqSetTarget(1) != CpuFreqSetStatus::TuneModeOff)
        PanicWithValue("arch/cpufreq", "P-state write not refused with tune mode off", 6);

    SerialWrite("[cpufreq-ctl-selftest] PASS (ratio admission + MSR splices + caps honesty + default-locked)\n");
}

} // namespace duetos::arch
