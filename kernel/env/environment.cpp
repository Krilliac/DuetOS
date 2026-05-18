#include "env/environment.h"

#include "acpi/acpi.h"
#include "acpi/srat.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "core/panic.h"
#include "cpu/topology.h"
#include "drivers/power/power.h"
#include "mm/frame_allocator.h"

namespace duetos::env
{

namespace
{

SystemEnvironment g_env{};

/// Decimal serial helper. The banner is a structural sentinel
/// written via raw SerialWrite (so it survives klog level demotion
/// and the boot-log analyzer can grep it); serial.h only ships a
/// hex formatter, so a tiny base-10 writer lives here.
void WriteDec(u64 v)
{
    char buf[21]; // 2^64 is 20 digits + NUL
    u32 i = sizeof(buf);
    buf[--i] = '\0';
    if (v == 0)
    {
        buf[--i] = '0';
    }
    while (v != 0 && i != 0)
    {
        buf[--i] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    arch::SerialWrite(&buf[i]);
}

EnvPlatform DerivePlatform(arch::HypervisorKind kind)
{
    if (arch::IsBareMetal())
    {
        return EnvPlatform::BareMetal;
    }
    if (kind == arch::HypervisorKind::QemuTcg || kind == arch::HypervisorKind::Bochs)
    {
        return EnvPlatform::Emulated;
    }
    return EnvPlatform::Virtualized;
}

EnvFormFactor DeriveFormFactor(bool chassis_is_laptop, u32 cpu_total)
{
    if (chassis_is_laptop)
    {
        return EnvFormFactor::Laptop;
    }
    // Coarse heuristic: a non-laptop with a high core count is
    // almost always a server/workstation; everything else is a
    // desktop. Refine only when a consumer needs finer than this
    // (anti-bloat — no SMBIOS chassis-subtype decode until then).
    if (cpu_total >= 8)
    {
        return EnvFormFactor::Server;
    }
    return EnvFormFactor::Desktop;
}

bool AnyHybridCore()
{
    const u32 limit = arch::SmpCpuIdLimit();
    for (u32 id = 0; id < limit; ++id)
    {
        const cpu::Topology* t = cpu::TopologyForCpu(id);
        if (t != nullptr && t->core_class != cpu::kCoreClassUnknown)
        {
            return true;
        }
    }
    return false;
}

void EmitBanner(const SystemEnvironment& e)
{
    arch::SerialWrite("[env] platform=");
    if (e.platform == EnvPlatform::BareMetal)
    {
        arch::SerialWrite("bare-metal");
    }
    else
    {
        arch::SerialWrite(arch::HypervisorName(e.hv_kind));
    }

    arch::SerialWrite(" cpu=");
    WriteDec(e.cpu_online);
    arch::SerialWrite("/");
    WriteDec(e.cpu_total);
    if (e.cpu_hybrid)
    {
        arch::SerialWrite("(hybrid)");
    }

    arch::SerialWrite(" ram=");
    WriteDec(e.ram_bytes >> 20);
    arch::SerialWrite("MiB mem=");
    if (e.numa)
    {
        arch::SerialWrite("NUMA(n");
        WriteDec(e.numa_nodes);
        arch::SerialWrite(")");
    }
    else
    {
        arch::SerialWrite("UMA");
    }

    arch::SerialWrite(" form=");
    arch::SerialWrite(EnvFormFactorName(e.form_factor));

    arch::SerialWrite(" pwr=");
    arch::SerialWrite(drivers::power::AcStateName(e.ac));
    arch::SerialWrite(" batt=");
    if (e.battery_percent == 255)
    {
        arch::SerialWrite("n/a");
    }
    else
    {
        WriteDec(e.battery_percent);
        arch::SerialWrite("%");
    }

    arch::SerialWrite(" temp=");
    if (e.cpu_temp_c == 0)
    {
        arch::SerialWrite("n/a");
    }
    else
    {
        WriteDec(e.cpu_temp_c);
        arch::SerialWrite("C");
    }

    arch::SerialWrite(" policy=");
    arch::SerialWrite(EnvPowerPolicyName(e.power_policy));
    arch::SerialWrite("\n");
}

} // namespace

EnvPowerPolicy EnvironmentDerivePolicy(const SystemEnvironment& e)
{
    // Thermal pressure trumps everything — back off regardless of
    // power source or form factor.
    if (e.thermal_throttle)
    {
        return EnvPowerPolicy::PowerSave;
    }
    // On battery: conserve.
    if (e.ac == drivers::power::kAcOffline)
    {
        return EnvPowerPolicy::PowerSave;
    }
    // Under a VMM/emulator the host owns real power management; a
    // balanced policy avoids fighting it and avoids spin-heavy
    // perf assumptions that punish a contended host.
    if (e.platform != EnvPlatform::BareMetal)
    {
        return EnvPowerPolicy::Balanced;
    }
    // Bare-metal laptop on AC: balanced (thermals/fan-noise matter
    // even when plugged in). Server/desktop on AC: full performance.
    if (e.form_factor == EnvFormFactor::Laptop)
    {
        return EnvPowerPolicy::Balanced;
    }
    return EnvPowerPolicy::Performance;
}

void EnvironmentInit()
{
    SystemEnvironment e{};

    const arch::HypervisorInfo& hv = arch::HypervisorInfoGet();
    e.hv_kind = hv.kind;
    e.platform = DerivePlatform(hv.kind);

    e.cpu_total = static_cast<u32>(acpi::CpuCount());
    e.cpu_online = static_cast<u32>(arch::SmpCpusOnline());
    if (e.cpu_total == 0)
    {
        // No MADT census (shouldn't happen post-AcpiInit, but keep
        // the banner honest rather than printing 0/0).
        e.cpu_total = e.cpu_online;
    }
    e.cpu_hybrid = AnyHybridCore();

    e.ram_bytes = mm::TotalFrames() * mm::kPageSize;
    e.numa = acpi::srat::SratPresent();
    e.numa_nodes = e.numa ? static_cast<u32>(acpi::srat::SratNodeCount()) : 1u;

    const drivers::power::PowerSnapshot ps = drivers::power::PowerSnapshotRead();
    e.form_factor = DeriveFormFactor(ps.chassis_is_laptop, e.cpu_total);
    e.ac = ps.ac;
    e.battery_state = ps.battery.state;
    e.battery_percent = (ps.battery.state == drivers::power::kBatNotPresent) ? 255 : ps.battery.percent;
    e.lid_present = ps.lid_present;
    e.lid_open = ps.lid_open;
    e.cpu_temp_c = ps.cpu_temp_c;
    e.pkg_temp_c = ps.package_temp_c;
    e.thermal_throttle = ps.thermal_throttle_hit;

    e.power_policy = EnvironmentDerivePolicy(e);
    e.valid = true;

    g_env = e;
    EmitBanner(g_env);
}

const SystemEnvironment& EnvironmentGet()
{
    return g_env;
}

EnvPowerPolicy EnvironmentPowerPolicy()
{
    return g_env.power_policy;
}

const char* EnvPlatformName(EnvPlatform p)
{
    switch (p)
    {
    case EnvPlatform::BareMetal:
        return "bare-metal";
    case EnvPlatform::Virtualized:
        return "virtualized";
    case EnvPlatform::Emulated:
        return "emulated";
    }
    return "unknown";
}

const char* EnvFormFactorName(EnvFormFactor f)
{
    switch (f)
    {
    case EnvFormFactor::Server:
        return "server";
    case EnvFormFactor::Desktop:
        return "desktop";
    case EnvFormFactor::Laptop:
        return "laptop";
    case EnvFormFactor::Unknown:
        return "unknown";
    }
    return "unknown";
}

const char* EnvPowerPolicyName(EnvPowerPolicy p)
{
    switch (p)
    {
    case EnvPowerPolicy::Performance:
        return "performance";
    case EnvPowerPolicy::Balanced:
        return "balanced";
    case EnvPowerPolicy::PowerSave:
        return "powersave";
    }
    return "unknown";
}

void EnvironmentSelfTest()
{
    const SystemEnvironment& e = EnvironmentGet();

    KASSERT(e.valid, "env", "EnvironmentInit did not run before self-test");
    KASSERT(e.cpu_online >= 1, "env", "online CPU census is zero");
    KASSERT(e.cpu_total >= e.cpu_online, "env", "total CPUs < online CPUs");

    // The invariant slice 2's monitor relies on: the cached policy
    // is exactly what the pure derivation yields for the snapshot.
    const EnvPowerPolicy rederived = EnvironmentDerivePolicy(e);
    KASSERT(EnvironmentPowerPolicy() == rederived, "env", "cached power policy diverged from derivation");

    // Name accessors must never return null (banner + shell rely on
    // this) and must cover every enumerator.
    KASSERT(EnvPlatformName(e.platform) != nullptr, "env", "platform name null");
    KASSERT(EnvFormFactorName(e.form_factor) != nullptr, "env", "form-factor name null");
    KASSERT(EnvPowerPolicyName(e.power_policy) != nullptr, "env", "policy name null");

    arch::SerialWrite("[env-selftest] PASS\n");
}

} // namespace duetos::env
