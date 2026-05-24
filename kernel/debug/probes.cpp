#include "debug/probes.h"

#include "log/klog.h"
#include "time/tick.h"
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
    {ProbeId::kRetpolineWild, "arch.retpoline_wild", ProbeArm::ArmedLog},
    {ProbeId::kIretqFrameWild, "arch.iretq_frame_wild", ProbeArm::ArmedLog},
    {ProbeId::kTrapDispatchRipScribble, "arch.trap_rip_scribble", ProbeArm::ArmedLog},
    {ProbeId::kSchedContextSwitchWildRet, "sched.ctxsw_wild_ret", ProbeArm::ArmedLog},
    {ProbeId::kAutonomicOutcomeMissed, "env.outcome_missed", ProbeArm::ArmedLog},
    {ProbeId::kBlendRangeOob, "video.blend_range_oob", ProbeArm::ArmedLog},
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

// Per-fire timeline ring. Tracks the LAST kProbeRingSlots fires
// across all probes (not just per-probe-counter). Each panic dump
// reads this back out so an investigator can see which probes
// fired in the seconds before the crash. Newest-first walk.
//
// Slot layout: (tick, caller_rip, value, probe_id, cpu_id, valid).
// Slot is filled lock-free via an atomic counter — collisions are
// impossible because the counter is monotonic and the slot index
// is unique per writer.
inline constexpr u32 kProbeRingSlots = 32;
struct ProbeRingEntry
{
    u64 tick;
    u64 caller_rip;
    u64 value;
    u16 probe_id;
    u16 cpu_id;
    u32 valid;
};
alignas(64) constinit ProbeRingEntry g_probe_ring[kProbeRingSlots] = {};
constinit u64 g_probe_ring_counter = 0;

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
    // Timeline ring entry. Cheap (one xadd + 4 stores) — adds
    // ~20 cycles on the armed-fire path; the disarmed fast path
    // is unaffected. Tick lookup uses TickCount() which is a
    // single u64 load.
    {
        const u64 ridx = __atomic_fetch_add(&g_probe_ring_counter, 1, __ATOMIC_RELAXED) % kProbeRingSlots;
        ProbeRingEntry* re = &g_probe_ring[ridx];
        __atomic_store_n(&re->valid, 0u, __ATOMIC_RELEASE);
        re->tick = ::duetos::time::TickCount();
        re->caller_rip = caller_rip;
        re->value = value;
        re->probe_id = static_cast<u16>(idx);
        re->cpu_id = 0; // SMP slice fills via CurrentCpu()->cpu_id once probes can call into cpu/percpu.h
        __atomic_store_n(&re->valid, 1u, __ATOMIC_RELEASE);
    }
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

u64 ProbeRingTotalFires()
{
    return __atomic_load_n(&g_probe_ring_counter, __ATOMIC_RELAXED);
}

u32 ProbeRingWalk(bool (*cb)(const ProbeRingFrame& f, void* ctx), void* ctx)
{
    if (cb == nullptr)
        return 0;
    const u64 total = ProbeRingTotalFires();
    if (total == 0)
        return 0;
    const u64 newest = (total - 1) % kProbeRingSlots;
    u32 visited = 0;
    for (u32 i = 0; i < kProbeRingSlots; ++i)
    {
        const u64 idx = (newest + kProbeRingSlots - i) % kProbeRingSlots;
        const ProbeRingEntry* e = &g_probe_ring[idx];
        if (__atomic_load_n(&e->valid, __ATOMIC_ACQUIRE) == 0)
            continue;
        ProbeRingFrame f;
        f.tick = e->tick;
        f.caller_rip = e->caller_rip;
        f.value = e->value;
        f.probe_id = e->probe_id;
        f.cpu_id = e->cpu_id;
        ++visited;
        if (!cb(f, ctx))
            break;
    }
    return visited;
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
