#include "debug/probes.h"

#include "log/klog.h"
#include "util/string.h"

namespace duetos::debug
{

namespace
{

struct ProbeRow
{
    ProbeId id;
    const char* name;
    ProbeArm default_arm;
};

// Static probe table. Order matches the ProbeId enum so we can
// index directly. Default arm state is curated — rare events
// that tell the operator something interesting are ArmedLog
// on first boot; high-volume events default Disarmed.
constexpr ProbeRow kProbeTable[] = {
    {ProbeId::kPanicEnter, "panic.enter", ProbeArm::ArmedLog},
    {ProbeId::kSandboxDenialCap, "sandbox.denial", ProbeArm::ArmedLog},
    {ProbeId::kWin32StubMiss, "win32.stub_miss", ProbeArm::ArmedLog},
    {ProbeId::kKernelPageFault, "mm.kernel_pagefault", ProbeArm::ArmedLog},
    {ProbeId::kKernelGpf, "trap.kernel_gpf", ProbeArm::ArmedLog},
    {ProbeId::kKernelUd, "trap.kernel_ud", ProbeArm::ArmedLog},
    {ProbeId::kMachineCheck, "trap.machine_check", ProbeArm::ArmedLog},
    {ProbeId::kChipsetNmi, "trap.chipset_nmi", ProbeArm::ArmedLog},
    {ProbeId::kHeapAllocFail, "mm.heap_alloc_fail", ProbeArm::ArmedLog},
    {ProbeId::kPhysAllocFail, "mm.phys_alloc_fail", ProbeArm::ArmedLog},
    {ProbeId::kSmpApOnline, "smp.ap_online", ProbeArm::ArmedLog},
    {ProbeId::kBootSelftestFail, "boot.selftest_fail", ProbeArm::ArmedLog},
    {ProbeId::kAcpiMcfgTruncated, "acpi.mcfg_truncated", ProbeArm::ArmedLog},
    {ProbeId::kPeLoaderOom, "loader.pe_oom", ProbeArm::ArmedLog},
    {ProbeId::kElfLoaderOom, "loader.elf_oom", ProbeArm::ArmedLog},
    {ProbeId::kProbeFail, "drivers.probe_fail", ProbeArm::ArmedLog},
    {ProbeId::kTopologyParseFailed, "topo.parse_failed", ProbeArm::ArmedLog},
    {ProbeId::kBootInitWedge, "boot.init_wedge", ProbeArm::ArmedLog},
    {ProbeId::kFaultInjectFired, "diag.fault_inject_fired", ProbeArm::ArmedLog},
    {ProbeId::kGpuRingBringupFail, "gpu.ring_bringup_fail", ProbeArm::ArmedLog},
    {ProbeId::kCurrentCpuGsbaseFallback, "cpu.gsbase_fallback", ProbeArm::ArmedLog},
    {ProbeId::kRing3Spawn, "ring3.spawn", ProbeArm::Disarmed},
    {ProbeId::kProcessCreate, "proc.create", ProbeArm::Disarmed},
    {ProbeId::kProcessDestroy, "proc.destroy", ProbeArm::Disarmed},
    {ProbeId::kPeLoadOk, "loader.pe_load", ProbeArm::Disarmed},
    {ProbeId::kElfLoadOk, "loader.elf_load", ProbeArm::Disarmed},
    {ProbeId::kThreadExit, "sched.thread_exit", ProbeArm::Disarmed},
    {ProbeId::kSchedContextSwitch, "sched.context_switch", ProbeArm::Disarmed},
    {ProbeId::kModuleStateChange, "module.state_change", ProbeArm::ArmedLog},
    {ProbeId::kLeakAttributable, "diag.leak_attributable", ProbeArm::ArmedLog},
    {ProbeId::kFixJournaled, "diag.fix_journaled", ProbeArm::ArmedLog},
    {ProbeId::kEnvPolicyChange, "env.policy_change", ProbeArm::ArmedLog},
    {ProbeId::kAutonomicAction, "env.autonomic_action", ProbeArm::ArmedLog},
    {ProbeId::kRcuWildCallback, "rcu.wild_callback", ProbeArm::ArmedLog},
    {ProbeId::kSchedTrampolineWildEntry, "sched.trampoline_wild_entry", ProbeArm::ArmedLog},
    {ProbeId::kIrqHandlerWild, "arch.irq_handler_wild", ProbeArm::ArmedLog},
};
static_assert(sizeof(kProbeTable) / sizeof(kProbeTable[0]) == static_cast<u64>(ProbeId::kCount),
              "kProbeTable size must match ProbeId::kCount — add a row for every enum entry");

// Live state. Indexed by ProbeId. arm[] is u8 (the enum) so
// loads are atomic on x86_64 — no lock needed on the fire
// path. fire_count[] is u64 counter; increments are non-
// atomic but worst case is one dropped count under contention
// (single-CPU today so contention is nil).
ProbeArm g_probe_arm[static_cast<u64>(ProbeId::kCount)] = {};
u64 g_probe_fires[static_cast<u64>(ProbeId::kCount)] = {};
bool g_inited = false;

} // namespace

void ProbeInit()
{
    for (const ProbeRow& row : kProbeTable)
    {
        g_probe_arm[static_cast<u64>(row.id)] = row.default_arm;
        g_probe_fires[static_cast<u64>(row.id)] = 0;
    }
    g_inited = true;
    KLOG_INFO("debug/probes", "probe subsystem online");
}

void ProbeFire(ProbeId id, u64 caller_rip, u64 value)
{
    const u64 idx = static_cast<u64>(id);
    if (idx >= static_cast<u64>(ProbeId::kCount))
        return;
    // Fast path: disarmed probe is a 1-byte load + compare + ret.
    // Intentionally no early-return for `!g_inited` — if ProbeInit
    // hasn't run the g_probe_arm[] is zero-filled = Disarmed, so
    // the comparison below takes the fast path anyway.
    const ProbeArm arm = g_probe_arm[idx];
    if (arm == ProbeArm::Disarmed)
        return;
    // Armed — count + log. The table is in ProbeId order (enforced
    // by the static_assert above) so the name is a direct index.
    ++g_probe_fires[idx];
    const char* name = kProbeTable[idx].name;
    if (value != 0)
    {
        KLOG_INFO_2V("debug/probes", name, "rip", caller_rip, "val", value);
    }
    else
    {
        KLOG_INFO_V("debug/probes", name, caller_rip);
    }
    // ArmedSuspend: phase 3 suspend-on-hit semantics would apply
    // here. Today this requires a TrapFrame* which probes don't
    // carry (they're plain call sites, not traps). Left for a
    // future slice — the infrastructure to park on a WaitQueue
    // from inside a plain kernel call is a separate problem from
    // parking from a trap handler. For now, ArmedSuspend behaves
    // like ArmedLog + a one-liner warning so the operator knows
    // it didn't actually suspend.
    if (arm == ProbeArm::ArmedSuspend)
    {
        KLOG_WARN_V("debug/probes", "ArmedSuspend not implemented for static probes (logged only), id",
                    static_cast<u64>(id));
    }
}

bool ProbeSetArm(ProbeId id, ProbeArm arm)
{
    const u64 idx = static_cast<u64>(id);
    if (idx >= static_cast<u64>(ProbeId::kCount))
        return false;
    g_probe_arm[idx] = arm;
    return true;
}

ProbeId ProbeByName(const char* name)
{
    if (name == nullptr)
        return ProbeId::kCount;
    for (const ProbeRow& row : kProbeTable)
    {
        if (duetos::core::StrEqual(row.name, name))
            return row.id;
    }
    return ProbeId::kCount;
}

u64 ProbeList(ProbeInfo* out, u64 cap)
{
    if (out == nullptr)
        return 0;
    const u64 n = static_cast<u64>(ProbeId::kCount);
    const u64 lim = (cap < n) ? cap : n;
    for (u64 i = 0; i < lim; ++i)
    {
        out[i].id = kProbeTable[i].id;
        out[i].name = kProbeTable[i].name;
        out[i].arm = g_probe_arm[i];
        out[i].fire_count = g_probe_fires[i];
    }
    return lim;
}

} // namespace duetos::debug
