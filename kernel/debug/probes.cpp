#include "probes.h"

#include "../core/klog.h"

namespace customos::debug
{

namespace
{

// Simple C string compare — no <string.h> in freestanding.
bool StrEqualLocal(const char* a, const char* b)
{
    while (*a != 0 && *b != 0)
    {
        if (*a != *b)
            return false;
        ++a;
        ++b;
    }
    return *a == *b;
}

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
    {ProbeId::kRing3Spawn, "ring3.spawn", ProbeArm::Disarmed},
    {ProbeId::kProcessCreate, "proc.create", ProbeArm::Disarmed},
    {ProbeId::kProcessDestroy, "proc.destroy", ProbeArm::Disarmed},
    {ProbeId::kSchedContextSwitch, "sched.context_switch", ProbeArm::Disarmed},
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
    // Armed — count + log. Find the name row for the line tag.
    ++g_probe_fires[idx];
    const char* name = "<unknown>";
    for (const ProbeRow& row : kProbeTable)
    {
        if (row.id == id)
        {
            name = row.name;
            break;
        }
    }
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
        if (StrEqualLocal(row.name, name))
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
        out[i].arm = g_probe_arm[static_cast<u64>(kProbeTable[i].id)];
        out[i].fire_count = g_probe_fires[static_cast<u64>(kProbeTable[i].id)];
    }
    return lim;
}

} // namespace customos::debug
